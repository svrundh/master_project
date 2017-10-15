# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Policy for deleting node(s) from a HTCondor pool.

"""
from oslo_log import log as logging
from senlin.common import consts
from senlin.policies import base
from senlin.common import schema
from senlin.common.i18n import _
from senlin.common import scaleutils as su
from senlin.engine import node as nm
from senlin.engine.actions import base as action_mod
from senlin.engine import dispatcher
import re
import threading
import datetime
import time
import paramiko
import StringIO
import json

LOG = logging.getLogger(__name__)


class HTCondorDeletionPolicy(base.Policy):

    VERSION = '1.0'
    VERSIONS = {
        '1.0': [
            {'status': consts.EXPERIMENTAL, 'since': '2017.06'}
        ]
    }

    PRIORITY = 400

    TARGET = [
        ('BEFORE', consts.CLUSTER_SCALE_IN),
        ('BEFORE', consts.CLUSTER_RESIZE),
        ('BEFORE', consts.CLUSTER_SCALE_OUT),
        ('AFTER', consts.CLUSTER_SCALE_IN),
        ('AFTER', consts.CLUSTER_RESIZE),
    ]

    PROFILE_TYPE = [
        'os.nova.server-1.0'
    ]

    KEYS = (
        CENTRAL_MANAGER_IP, SSH_KEY, USER_NAME, GRACEFUL_SHUTDOWN_TIME_LIMIT, DELETE_REPEAT_INTERVAL,
    ) = (
        'central_manager_ip', 'ssh_key', 'user_name', 'graceful_shutdown_time_limit', 'delete_repeat_interval',
    )

    properties_schema = {
        CENTRAL_MANAGER_IP: schema.String(
            _('IP of the HTCondor pool central manager.'),
            required=True
        ),
        SSH_KEY: schema.String(
            _('SSH key (RSA) to log onto central manager.'),
            required=True
        ),
        USER_NAME: schema.String(
            _('User name for logging onto the central manager.'),
            required=True
        ),
        GRACEFUL_SHUTDOWN_TIME_LIMIT: schema.Integer(
            _('Time limit in seconds before node is terminated preemptively. '
              'A value of -1 indicates that there is no limit.'),
            default=-1
        ),
        DELETE_REPEAT_INTERVAL: schema.Integer(
            _('Time in seconds before node delete is reattempted during draining event.'),
            default=600
        )
    }

    def __init__(self, name, spec, **kwargs):
        super(HTCondorDeletionPolicy, self).__init__(name, spec, **kwargs)

        self.central_manager_ip = self.properties[self.CENTRAL_MANAGER_IP]
        self.user_name = self.properties[self.USER_NAME]
        self.graceful_shutdown_time_limit = self.properties[self.GRACEFUL_SHUTDOWN_TIME_LIMIT]
        self.delete_repeat_interval = self.properties[self.DELETE_REPEAT_INTERVAL]

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.ssh_key = paramiko.RSAKey.from_private_key(StringIO.StringIO(self.properties[self.SSH_KEY]))

    @staticmethod
    def _set_residuals_count(action, count):
        residuals = {
            'residuals': count
        }

        if action.entity.data.get('residuals', 0) == 0:
            residuals.update({'draining_start_time': datetime.datetime.utcnow()})

        action.entity.data.update(residuals)
        action.entity.store(action.context)

    @staticmethod
    def _remove_residuals(action, count):
        if count < action.entity.data.get('residuals', 0):
            action.entity.data['residuals'] -= min(count, action.entity.data['residuals'])
        else:
            action.entity.data['residuals'] = 0

        action.entity.store(action.context)

    @staticmethod
    def _start_residuals_cleanup(action, nodes=None):
        values = {
            'data': {
                'residual_deletion': True,
                'deletion': {'count': 0}
            },
            'status': action_mod.Action.READY
        }

        if nodes:
            values.update({'nodes': nodes})

        action_mod.Action.create(action.context, action.entity.id, action_mod.consts.CLUSTER_RESIZE, **values)
        dispatcher.start_action()

    def _execute_ssh_command(self, command):
        # Open SSH connection to condor central manager
        self.ssh_client.connect(self.central_manager_ip, username=self.user_name, pkey=self.ssh_key)

        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        error = stderr.read()

        if error:
            raise Exception('Command "' + command + '" failed with error: ' + error)

        # Close SSH connection to condor central manager
        self.ssh_client.close()

        return stdin, stdout

    def _start_draining(self, action, nodes=None):
        stdin, stdout = self._execute_ssh_command('condor_status -json -attributes Machine,MyAddress')

        condor_workers = [elem for elem in json.loads(stdout.read() or '[]')]
        nodes = nodes or action.entity.nodes

        workers_to_drain = [worker['MyAddress'] for worker in condor_workers if
                            [node for node in nodes if self._condorname_senlinnode_match(action, worker['Machine'],
                                                                                         node,)]]

        command_list = ['PATH=$PATH:/usr/sbin;']
        for worker in workers_to_drain:
            command_list.append('condor_config_val -name "' + worker + '" -startd -rset "START = False" ' +
                           '"DRAIN_TIMESTAMP = ' + str(int(time.time())) + '";')
            command_list.append('condor_reconfig "' + worker + '";')

        commands = "".join(command_list)
        self._execute_ssh_command(commands)

    def _stop_draining(self, action, nodes=None):
        stdin, stdout = self._execute_ssh_command('condor_status -json -attributes Machine,MyAddress')

        condor_workers = [elem for elem in json.loads(stdout.read() or '[]')]

        if nodes is None:
            nodes = action.entity.nodes

        workers_to_stop_draining = [worker['MyAddress'] for worker in condor_workers if
                                    [node for node in nodes if
                                     self._condorname_senlinnode_match(action, worker['Machine'], node,)]]

        command_list = ['PATH=$PATH:/usr/sbin;']
        for worker in workers_to_stop_draining:
            command_list.append('condor_config_val -name "' + worker + '" -startd -rset "START = True";')
            command_list.append('condor_config_val -name "' + worker + '" -startd -runset DRAIN_TIMESTAMP;')
            command_list.append('condor_reconfig "' + worker + '";')

        commands = "".join(command_list)
        self._execute_ssh_command(commands)

    # Matches a HTCondor name against a senlin node.
    def _condorname_senlinnode_match(self, action, condor_name, node):
        htcondor_ip_name_re = r'(([0-9]{1,3}-){3}[0-9]{1,3})'
        match = re.search(htcondor_ip_name_re, condor_name)

        if match:
            engine_node = nm.Node.load(action.context, db_node=node)
            ip_re = r'(([0-9]{1,3}\.){3}[0-9]{1,3})'
            server_ips = [i[0] for i in re.findall(ip_re, str(engine_node.get_details(action.context)['addresses']))]
            condor_ip = match.group(1).replace('-', '.')
            return condor_ip in server_ips
        else:
            return condor_name == node.name

    @staticmethod
    def _update_action(action, victims):
        pd = action.data.get('deletion', {})
        pd['count'] = len(victims)
        pd['candidates'] = victims
        action.data.update({
            'status': base.CHECK_OK,
            'reason': _('Candidates generated'),
            'deletion': pd
        })
        action.store(action.context)

    def pre_op(self, cluster_id, action):
        """Choose victims that can be deleted.

        :param cluster_id: ID of the cluster to be handled.
        :param action: The action object that triggered this policy.
        """

        # Stop draining if action creating nodes is performed
        if action.data.get('creation', {}).get('count', 0) > 0:
            self._remove_residuals(action, action.entity.data.get('residuals', 0))
            self._stop_draining(action)
            # Timer
            end = time.time()
            LOG.debug("Pre_op timer2: " + str(end - start) + " Nodes: " + str(len(action.entity.nodes)))

            return

        cluster = action.entity
        deletion = action.data.get('deletion', {})

        # If residuals cleanup, set count to number of residuals
        if 'residual_deletion' in action.data:
            if action.entity.data.get('residuals', 0) == 0:
                self._update_action(action, [])
                return
            count = action.entity.data['residuals']

        elif deletion:
            # there are policy decisions
            count = deletion['count']
        # No policy decision, check action itself: SCALE_IN
        elif action.action == consts.CLUSTER_SCALE_IN:
            count = action.inputs.get('count', 1)

        # No policy decision, check action itself: RESIZE
        else:
            current = len(cluster.nodes)
            res, reason = su.parse_resize_params(action, cluster, current)
            if res == base.CHECK_ERROR:
                action.data['status'] = base.CHECK_ERROR
                action.data['reason'] = reason
                LOG.error(reason)
                return

            if 'deletion' not in action.data:
                return
            count = action.data['deletion']['count']

        if count > len(cluster.nodes):
            count = len(cluster.nodes)

        # Querying HTCondor central manager for busy workers
        stdin, stdout = self._execute_ssh_command('condor_status -json -attributes '
                                                  'Machine -constraint \'Activity == "Busy"\'')
        busy_workers = [elem['Machine'] for elem in json.loads(stdout.read() or '[]')]

        # Finding nodes in the cluster not in list of busy workers (and error nodes)
        candidates = [node for node in cluster.nodes if node.status != "ACTIVE" or not
                      [worker for worker in busy_workers if self._condorname_senlinnode_match(action, worker, node)]]

        # Make sure candidates do not take on a job before they are deleted
        self._start_draining(action, candidates)

        # Check that they have not taken on a job before drain was called
        stdin, stdout = self._execute_ssh_command('condor_status -json -attributes '
                                                  'Machine -constraint \'Activity == "Busy"\'')
        busy_workers = [elem['Machine'] for elem in json.loads(stdout.read() or '[]')]
        for candidate in candidates:
            if [worker for worker in busy_workers if self._condorname_senlinnode_match(action, worker, candidate)]:
                self._stop_draining(action, [candidate])
                candidates.remove(candidate)

        if len(candidates) < count:

            # Checks if draining timeout is reached for previous deletion attempt
            # and adds nodes to be preempted to candidates
            if 'residuals' in action.entity.data and self.graceful_shutdown_time_limit >= 0:
                now = datetime.datetime.utcnow()
                if (now - datetime.datetime.strptime(action.entity.data['draining_start_time'],
                                                     '%Y-%m-%dT%H:%M:%S.%f')).seconds > self.graceful_shutdown_time_limit:
                    preempt_count = count - len(candidates)  # min(count, action.entity.data['residuals'])
                    preempt_candidates = [node for node in cluster.nodes if node not in candidates]
                    nodes_to_be_preempted = [nm.Node.load(action.context, node_id) for node_id in
                                             su.nodes_by_age(preempt_candidates, preempt_count, True)]
                    candidates.extend(nodes_to_be_preempted)

            # Adds residuals if 'count' nodes could not be removed. If there are already residuals
            # waiting to be deleted, residuals is set to the highest of count - candidates and residuals.
            # This avoids too many residuals to be added as result of repeated delete attempts.
            # self._set_residuals_count(action, max(count - len(candidates), action.entity.data.get('residuals', 0)))
            if count > action.entity.data.get('residuals', 0):
                self._set_residuals_count(action, count - len(candidates))
            else:
                self._set_residuals_count(action, action.entity.data.get('residuals'))
                action.data.update({'residuals_deletion': True})

            self._start_draining(action)

            count = len(candidates)
        elif action.entity.data.get('residuals', 0) > 0:
            action.data.update({'residuals_deletion': True})
            action.store(action.context)

        victims = su.nodes_by_age(candidates, count, True)

        # Stop draining the nodes that were not selected
        self._stop_draining(action, [node for node in candidates if node.id not in victims])

        self._update_action(action, victims)

        return

    def post_op(self, cluster_id, action):
        start = time.time()

        # Set residual count to honor exact capacity request
        if action.inputs.get('adjustment_type', '') == 'EXACT_CAPACITY':
            if action.inputs.get('number') < action.entity.max_size:
                diff = len(action.entity.nodes) - action.inputs.get('number')
                if diff >= 0:
                    self._set_residuals_count(action, diff)

        if 'residual_deletion' in action.data:
            self._remove_residuals(action, action.data['deletion']['count'])

        if action.entity.data.get('residuals', 0) == 0:
            self._stop_draining(action)
        else:
            self._start_draining(action)
            timer = threading.Timer(self.delete_repeat_interval, self._start_residuals_cleanup, [action])
            timer.start()

        return
