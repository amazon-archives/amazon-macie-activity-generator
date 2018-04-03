"""
Copyright 2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
Licensed under the Amazon Software License (the "License"). You may not use this file
except in compliance with the License. A copy of the License is located at
http://aws.amazon.com/asl/
or in the "license" file accompanying this file. This file is distributed on an "AS IS"
BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under the License.

Description: Anomaly detection systems (i.e. Amazon Macie) often perform quantitative
analytics over timeseries derived from activities on their monitored subjects. While
the core anomaly detection algorithms can be tested in isolation using test vectors,
testing and measuring end to end performance and accuracy of these systems remain a
challenge.

amazon-macie-activity-generator aims to address at least a subset of these challenges
via providing a platform to facilitate timeseries generation, noise addition, anomaly
injection and execution on target subjects over an extended period of time. This platform
offers generating synthetic timeseries as well as replaying real timeseries
gathered from monitoring subjects in the past.

SECURITY WARNING: Blueprint files are assumed to contain only trusted content and
vetted by amazon-macie-activity-generator stack operators prior to deployment. You need to
fundamentally think of blueprints as executable codes which will have access to all things
(i.e. computing environment, credentials) as amazon-macie-activity-generator lambda functions.
amazon-macie-activity-generator uses python's "eval" to evaluate formulas for anomaly injection
and custom shape timeseries generation. Hence, If you ever allow untrusted blueprints to be used
for running amazon-macie-activity-generator that is basically opening up a fully fledged
code-injection path.

Please refrain from setting up amazon-macie-activity-generator stacks with blueprints provided
by untrusted individuals or systems. Similarly amazon-macie-activity-generator stack owners/operators
are responsible for actions executed on targets (i.e. GetObject on a S3 bucket) based on their blueprints.
"""

import os
import sys
import boto3
import json
import math
import random
import uuid
import logging
import time
import textwrap
import base64
import string

import timesynth as ts
import numpy as np

from datetime import datetime
from scipy import signal
from faker import Faker
from threading import Thread
from faker.providers import BaseProvider
from botocore.exceptions import ClientError

TIMESERIES_QUEUE_MAX_BATCH_ENTRIES = 10
TIMESERIES_QUEUE_URL = os.environ['TimeSeriesQueue']
CLOUDWATCH_METRIC_DATA_MEMBERS_MAX = 10
S3_LIST_OBJECTS_MAX = 1000

BLUEPRINT_S3_BUCKET_NAME = os.environ['BlueprintBucket']
BLUEPRINT_S3_OBJECT_KEY = os.environ['BlueprintObject']
DEFAULT_S3_BUCKET = os.environ['DefaultS3Bucket']

DEFAULT_SIGNAL_MIN = 1
DEFAULT_SIGNAL_MAX = 20

DEFAULT_NOISE_MIN = 0
DEFAULT_NOISE_MAX = 0

DEFAULT_NUM_POINTS = 100

def get_list_chunks(data, chunks_num):
    """
    Breaks a list to chunks with a given maximum chunk size

    @param data: input list to be broken to chunks
    @param checks_num: maximum size of chunks to create

    @return: list of chunks created from input list
    """

    for i in xrange(0, len(data), chunks_num):
        yield data[i:i + chunks_num]

def get_rand_string(len, chars = string.letters):
    """
    Create a random string with a given length and content characters

    @param len: length of random string
    @param chars: list of characters to use for generating the string

    @return: a string with random content
    """
    return ''.join(random.choice(chars) for x in range(len))

def slice_num(num, slice_size):
    """
    Break a given number to requested slice sizes

    @param num: a number to be sliced up
    @param slice_size: maximum size of slices to be extracted

    @return: a list of slices extracted from the given number
    """

    # Return the number if not sliceable to requested slices.
    if (num == 0 or slice_size <= 0):
        return [num]

    slices = np.full(num/slice_size, slice_size).tolist()
    if num % slice_size > 0:
        slices.append(num % slice_size)

    return slices

class FakeIdentifiers(BaseProvider):

    def itin(self):
        """
        Create a fake Individual Taxpayer Identification Number (ITIN)
        """

        return '9%02d-7%d-%04d' % (
            random.randint(0, 99), random.randint(0, 9),
            random.randint(0, 9999))

    def swift_code(self):
        """
        Create a fake SWIFT codes (International bank codes that identifies
        particular banks worldwide)
        """

        code = (get_rand_string(len = 4, chars = string.uppercase) +
            random.choice(['GB', 'US', 'DE', 'RU', 'CA', 'JP', 'CN']) +
            get_rand_string(len = 2, chars = string.uppercase))

        if random.random() > 0.5:
            code += get_rand_string(len = 3, chars = string.uppercase)

        return code

    def cve(self):
        """
        Create a fake Common Vulnerabilities and Exposures (CVE) identifier
        """

        return 'CVE-%d-%04d' % (
            random.randint(1999, datetime.now().year),
            random.randint(1, random.choice(
                [9999, 99999, 999999, 9999999])))

class FakeCredentials(BaseProvider):

    BASE64_CHARS = string.letters + string.digits + '+/'

    def aws_creds(self):
        """
        Create a fake set of temporary or long lived AWS credentials
        """

        access_key = ''.join(
            random.choice(string.uppercase)
            for x in range(16))

        secret_key = ''.join(
            random.choice(self.BASE64_CHARS)
            for x in range(40))

        token = None
        if random.random() > 0.5:
            access_key = 'ASIA' + access_key

            token = 'FQoDYXdzEJb//////////wEaD' + ''.join(
                random.choice(self.BASE64_CHARS)
                for x in range(471))
        else:
            access_key = 'AKIA' + access_key

        creds = 'aws_access_key_id=%s\r\n' % access_key
        creds += 'aws_secret_access_key=%s\r\n' % secret_key

        if token:
            creds += 'aws_session_token=%s\r\n' % token

        return creds

    def slack_creds(self):
        """
        Create fake Slack API credential token
        """

        creds = 'slack_token=' + random.choice(
            ['xoxa-', 'xoxp-', 'xoxb-', 'xoxo-'])

        if random.random() > 0.5:
            creds += '%s-%s-%s-%s\r\n' % (
                get_rand_string(4, string.digits),
                get_rand_string(4, string.digits),
                get_rand_string(5, string.digits),
                get_rand_string(10, string.digits))
        else:
            creds += '%s-%s\r\n' % (
                get_rand_string(11, string.digits),
                get_rand_string(15, string.digits))

        return creds

    def github_creds(self):
        """
        Create fake Github access credentials
        """

        return (random.choice(
            ['GITHUB_SECRET', 'GITHUB_KEY', 'github_secret',
             'github_key', 'github_token', 'GITHUB_TOKEN',
             'github_api_key', 'GITHUB_API_KEY']) + ':"' +
            get_rand_string(40, string.letters + string.digits) + '"\r\n')

    def facebook_creds(self):
        """
        Create fake Facebook API access credentials
        """

        return (random.choice(
            ['facebook_secret', 'FACEBOOK_SECRET',
             'facebook_app_secret', 'FACEBOOK_APP_SECRET']) + '="' +
            get_rand_string(32, string.hexdigits).lower() + '"\r\n')

    LINUX_USER_NAMES = [
        'root', 'games', 'bin', 'daemon', 'adm', 'lp',
        'mail', 'uucp', 'operator', 'gopher', 'ftp', 'nobody',
        'rpc', 'ntp', 'saslauth', 'dbus', 'tcpdump',
        'mailnull', 'smmsp', 'rpcuser', 'nfsnobdy', 'sshd'
    ]

    def linux_passwd(self):
        """
        Create a fake Linux password file
        """

        random.shuffle(self.LINUX_USER_NAMES)

        passwd_file = ''
        for index in xrange(random.randint(
            len(self.LINUX_USER_NAMES)/2, len(self.LINUX_USER_NAMES) - 1)):
            user_name = self.LINUX_USER_NAMES[index]
            passwd_file += (
                user_name + ':' +
                random.choice(['*','x']) + ':' +
                str(random.randint(1, 65535)) + ':' +
                str(random.randint(1, 65535)) + ':' +
                user_name + ':' +
                '/usr/' + user_name + ':' +
                '/sbin/nologin\r\n')

        return passwd_file

    def linux_shadow(self):
        """
        Create a fake Linux shadow file
        """

        random.shuffle(self.LINUX_USER_NAMES)

        shadow_file = ''
        for index in xrange(random.randint(
            len(self.LINUX_USER_NAMES)/2, len(self.LINUX_USER_NAMES) - 1)):
            shadow_file += (
                self.LINUX_USER_NAMES[index] + ':' +
                random.choice(['*','!!','*LOCK*']) + ':' +
                str(random.randint(1000, 10000)) + ':' +
                str(random.randint(1, 10)) + ':' +
                str(random.randint(1, 10)) + ':' +
                str(random.randint(1, 10)) + ':' +
                str(random.randint(10, 100)) + ':' +
                str(random.randint(10, 100)) + ':\r\n')

        return shadow_file

class FakeCrypto(BaseProvider):

    def rsa(self):
        """
        Create a PEM formatted fake RSA private key
        """
        return self.__get_pem('RSA PRIVATE KEY')

    def dsa(self):
        """
        Create a PEM formatted fake DSA private key
        """
        return self.__get_pem('DSA PRIVATE KEY')

    def ec(self):
        """
        Create a PEM formatted fake EC private key
        """
        return self.__get_pem('EC PRIVATE KEY')

    def cert(self):
        """
        Create a PEM formatted X509 certificate
        """
        return self.__get_pem('CERTIFICATE')

    def pgp(self):
        """
        Create a PEM formatted PGP private key block
        """
        id = 'PGP PRIVATE KEY BLOCK'
        return (self.__get_header(id) + 'Version: GnuPG v1.2.3 (OS/2)\r\n\r\n' +
            self.__get_body(prefix = 'lQ') + self.__get_footer(id))

    def __get_pem(self, id, prefix = 'MI'):
        return self.__get_header(id) + self.__get_body(prefix) + self.__get_footer(id)

    def __get_header(self, id):
        return '-----BEGIN %s-----\r\n' % id

    def __get_footer(self, id):
        return '\r\n-----END %s-----\r\n' % id

    def __get_body(self, prefix):
        """
        Create a random base64 encoded string for body of PEM formatted data
        """
        return "\r\n".join(textwrap.wrap(prefix + base64.b64encode(
            "".join([random.choice(string.ascii_letters) for n in xrange(800)])), 64))

def create_faker():
    """
    Create a faker object with added activity-generator's own fake data providers
    """

    faker = Faker()
    faker.add_provider(FakeCrypto)
    faker.add_provider(FakeCredentials)
    faker.add_provider(FakeIdentifiers)
    return faker

def scale_range(input, min, max):
    """
    Rescales a given list of numbers to a given range

    @param input: a list of numbers to be rescaled
    @param min: minimum value for the rescaling range
    @param max: maximum value for the rescaling range

    @return: a list of rescaled numbers
    """

    input_min = float(np.min(input))
    input_max = float(np.max(input))

    input_std = np.subtract(input, input_min) / (input_max - input_min)
    input_scaled = input_std * (max - min) + min

    return np.ceil(input_scaled)

def scale_noise(input, configuration):
    """
    Rescale a list of noise values based on the timeseries generator configuration

    @param input: list of noise values
    @param configuration: configuration for the corresponding timeseries generator

    @return: a list of rescaled noise values
    """

    return scale_range(input,
        min = get_noise_min(configuration),
        max = get_noise_max(configuration))

def get_num_points(configuration):
    """
    @param configuration: configuration of a timeseries generator
    @return: total number of data points to create for a timeseries generator
    """
    return configuration.get('num_points', DEFAULT_NUM_POINTS)

def get_noise_min(configuration):
    """
    @param configuration: configuration of a timeseries generator
    @return: minimum value of noise to be added on timeseries data points
    """
    return configuration.get('noise_min', DEFAULT_NOISE_MIN)

def get_noise_max(configuration):
    """
    @param configuration: configuration of a timeseries generator
    @return: maximum value of noise to be added on timeseries data points
    """
    return configuration.get('noise_max', DEFAULT_NOISE_MAX)

def get_signal_min(configuration):
    """
    @param configuration: configuration of a timeseries generator
    @return: minimum value of data points to be generated
    """
    return configuration.get('signal_min', DEFAULT_SIGNAL_MIN)

def get_signal_max(configuration):
    """
    @param configuration: configuration of a timeseries generator
    @return: maximum value of data points to be generated
    """
    return configuration.get('signal_max', DEFAULT_SIGNAL_MAX)

def scale_signal(input, configuration):
    """
    Rescale data points of a timeseries based on its configuration

    @param input: a list of data points from a timeseries
    @param configuration: configuration of a timeseries generator

    @return: a list of rescaled data points
    """

    return scale_range(input,
        min = get_signal_min(configuration),
        max = get_signal_max(configuration))

def call_local_func(func_name, func_args):
    """
    Dynamically call a function from the current module

    @param func_name: name of a function from the current model
    @param func_args: dictionary of arguments to be passed to the target function

    @return: returned value from calling the target function
    """

    return call_object_method(sys.modules[__name__], func_name, func_args)

def call_object_method(obj, method_name, method_args):
    """
    Dynamically call a method from a given object

    @param obj: target object
    @param method_name: name of a method to be called
    @param method_args: dictionary of arguments to be passed to the target method

    @return: returned value from calling the target method
    """

    return getattr(obj, method_name)(**method_args)

def get_square_timeseries(configuration):
    """
    @param configuration: timeseries configuration defining attributes of data points
    @return: a list of sqaure-shaped data points based on given configuration
    """

    samples = []
    while len(samples) < get_num_points(configuration):
        samples += np.full(
            configuration.get('low_width', 1),
            configuration.get('low_value', 0)).tolist()
        samples += np.full(
            configuration.get('high_width', 1),
            configuration.get('high_value', 0)).tolist()

    return samples[:get_num_points(configuration)]

def get_custom_timeseries(configuration):
    """
    @param configuration: timeseries configuration defining attributes of data points
    @return: a list of rescaled custom-shaped data points based on given configuration
    """

    # activity-generator customers are warned of using eval in activity-generator,
    # hence they must not be accepting blueprints from untrusted individuals or systems.
    # Otherwise, this use of eval opens them up to code-injection exploits.
    datapoints = []
    for t in xrange(get_num_points(configuration)):
        datapoints.append(eval(configuration['formula'], locals()))

    return scale_signal(datapoints, configuration).tolist()

def get_sinusoidal_timeseries(configuration):
    """
    @param configuration: timeseries configuration defining attributes of data points
    @return: a list of rescaled sinusoidal-shaped data points based on given configuration
    """

    time_sampler = ts.TimeSampler(
        stop_time = get_num_points(configuration))

    regular_time_samples = time_sampler.sample_regular_time(
        num_points = get_num_points(configuration))

    sinusoid = ts.signals.Sinusoidal(
        frequency = configuration.get('frequency', 1.0),
        amplitude = configuration.get('amplitude', 1.0))

    timeseries = ts.TimeSeries(sinusoid)
    datapoints = timeseries.sample(regular_time_samples)[0]

    return scale_signal(datapoints, configuration).tolist()

def get_constant_timeseries(configuration):
    """
    @param configuration: timeseries configuration defining attributes of data points
    @return: a list of constant data points based on given configuration
    """

    return np.full(
        get_num_points(configuration),
        configuration.get('constant', 1)).tolist()

def get_real_timeseries(configuration):
    """
    @param configuration: timeseries configuration defining attributes of data points
    @return: a list of rescaled real data points extracted from a given S3 object
    """

    timeseries = s3_client.get_object(
        Bucket = configuration['bucket'],
        Key = configuration['key'])['Body'].read()

    timeseries = [
        int(numeric_string)
        for numeric_string in timeseries.splitlines()
        if numeric_string.strip() != '']

    if len(timeseries) < get_num_points(configuration):
        timeseries += np.full(
            get_num_points(configuration) - len(timeseries), 0).tolist()

    return scale_signal(timeseries[:get_num_points(configuration)], configuration)

def get_random_timeseries(configuration):
    """
    @param configuration: timeseries configuration defining attributes of data points
    @return: a list of randomly generated data points based on given configuration
    """

    samples = []
    type = configuration.get('type', 'uniform')

    if type == 'triangular':
        for index in xrange(get_num_points(configuration)):
            samples.append(random.triangular(
                low = get_signal_min(configuration),
                high = get_signal_max(configuration)))
    else:
        for index in xrange(get_num_points(configuration)):
            datapoint = 0
            if type == 'uniform':
                datapoint = random.random()
            elif type in ['betavariate', 'gammavariate', 'weibullvariate']:
                datapoint = call_obj_method(type, {
                    'alpha': configuration.get('alpha', 1.0),
                    'beta': configuration.get('beta', 1.0)})
            elif type in ['gauss', 'normalvariate', 'lognormvariate']:
                datapoint = call_obj_method(type, {
                    'mu': configuration.get('mu', 0.0),
                    'sigma': configuration.get('sigma', 1.0)})
            elif type == 'expovariate':
                datapoint = random.expovariate(
                    lambd = configuration.get('lambda', 1.0))
            elif type == 'vonmisesvariate':
                datapoint = random.vonmisesvariate(
                    mu = configuration.get('mu', 0.0),
                    kappa = configuration.get('kappa', 1.0))
            elif type == 'paretovariate':
                datapoint = random.paretovariate(
                    alpha = configuration.get('alpha', 1.0))

            samples.append(datapoint)

        samples = scale_signal(samples, configuration).tolist()

    return samples

def fill_timeseries_queue(queue_entries):
    """
    Slice up given SQS message entries to maximum allowed batches and send them
    to target SQS queue.

    @param queue_entries: a list of SQS message entries containing data points
    """

    for queue_entries_chunk in get_list_chunks(
        data = queue_entries, chunks_num = TIMESERIES_QUEUE_MAX_BATCH_ENTRIES):
            sqs_client.send_message_batch(
                QueueUrl = TIMESERIES_QUEUE_URL, Entries = queue_entries_chunk)

def apply_noise(datapoints, configuration):
    """
    Apply random noise to given data points based on configuration of their generator

    @param datapoints: a list of data points from a timeseries
    @param configuration: configuration of data points generator

    @return: a list of data points with added/substracted noise values
    """

    noised_datapoints = datapoints
    if (get_noise_min(configuration) and get_noise_max(configuration)):
        noise = np.random.normal(0, 1, len(datapoints))
        noise = scale_noise(noise, configuration)
        noised_datapoints = [max(0, x + y) for x, y in zip(datapoints, noise)]

    return noised_datapoints

def apply_anomalies(datapoints, configuration):
    """
    Inject anomalies to given data points based on configuration of their generator

    @param datapoints: a list of data points from a timeseries
    @param configuration: configuration of data points generator

    @return: a list of data points with injected anomalies
    """

    # Accomodate configurations with more than one set of anomalies configuration
    all_anomalies = configuration.get('anomalies', [])
    if isinstance(all_anomalies, dict):
        all_anomalies = [all_anomalies]

    for anomalies in all_anomalies:
        start_point = min(anomalies.get('start', 0), len(datapoints) - 1)
        end_point = min(anomalies.get('end', len(datapoints) - 1), len(datapoints) - 1)
        # Anomalies might be only configured in commons and datapoints for a generator
        # might not fall in the range defined there. Hence, we confirm anomaly injection
        # is in fact feasible for the current data points.
        if (start_point <= len(datapoints) - 1 and end_point <= len(datapoints) - 1):
            datapoint_max = int(np.max(datapoints))
            for _ in xrange(anomalies.get('counts', 0)):
                t = random.randint(start_point, end_point)
                # activity-generator customers are warned of using eval in activity-generator,
                # hence they must not be accepting blueprints from untrusted
                # individuals or systems. Otherwise, this use of eval opens
                # them up to code-injection exploits.
                anomaly_formula = anomalies.get('formula')
                if anomaly_formula:
                    datapoints[t] = eval(anomaly_formula, locals())
                else:
                    datapoints[t] = (datapoint_max + 1) ** 2

    return datapoints

def generate_datapoints():
    """
    Generate data points, apply noise and inject anomalies on them based on defined
    timeseries generators in the blueprint.

    @return: a dictionary of data points for all timeseries generators in the blueprint
    """

    datapoints = {}
    for generator in blueprint['generators']:

        generator_func_name = 'get_%s_timeseries' % (generator['shape'])

        cur_datapoints = call_local_func(
            generator_func_name, {'configuration': generator['config']})

        cur_datapoints = apply_noise(cur_datapoints, generator['config'])
        cur_datapoints = apply_anomalies(cur_datapoints, generator['config'])

        # Convert all datapoints to integers and avoid unnencessary type casts.
        datapoints[generator['id']] = np.array(cur_datapoints).astype(int).tolist()

    return datapoints

def produce_timeseries():
    """
    Generate data points, package them into a list of SQS message entries and pass
    them on to the target SQS FIFO queue.
    """

    datapoints = generate_datapoints()

    queue_entries = []

    # For timeseries produced in shorter than 5 minutes time intervals,
    # we need to ensure uniqueness of message deduplication ids. Otherwise,
    # FIFO SQS queue would ignoring them. Hence, we use the combincation of
    # current time (shared for each batch) + entry index (unique for each batch)
    # as deduplication id.
    timeseries_batch_id = str(int(time.time() * 1000))

    max_num_points = len(max(datapoints.values()))

    for datapoint_index in xrange(max_num_points):

        queue_entry_body = {}
        for generator in blueprint['generators']:
            # If a generator has generator data points less than others,
            # then it gets zero data points for the remaining time slots.
            if datapoint_index >= len(datapoints[generator['id']]):
                queue_entry_body[generator['id']] = 0
            else:
                datapoint_value = datapoints[generator['id']][datapoint_index]
                queue_entry_body[generator['id']] = datapoint_value

        # Convert entry_id to string as needed for Id type in SQS messages.
        entry_id = str(len(queue_entries))
        deduplication_id = '%s:%s' % (timeseries_batch_id, entry_id)

        queue_entries.append({
            'Id': entry_id,
            'MessageBody': json.dumps(queue_entry_body),
            'MessageGroupId': 'timeseries',
            'MessageDeduplicationId': deduplication_id
        })

    fill_timeseries_queue(queue_entries)

def consume_datapoints(timestamp):
    """
    Retrieve and parse a single message from the SQS queue and dispatch to targets.

    @param timestamp: the time slot for retrieved data points from SQS queue

    @return: number of messages retrieved
    """

    messages = sqs_client.receive_message(
        QueueUrl = TIMESERIES_QUEUE_URL,
        MaxNumberOfMessages = 1).get('Messages', [])

    if len(messages) > 0:
        # Delete the message from the queue right away as we need to
        # process the datapoints now or never. activity-generator works on a best
        # effort basis and if it fails to execute a datapoint during its own timeslot,
        # the datapoint will be skipped.
        sqs_client.delete_message(
            QueueUrl = TIMESERIES_QUEUE_URL,
            ReceiptHandle = messages[0]['ReceiptHandle'])
        datapoints = json.loads(messages[0]['Body'])

        dispatch_datapoints_to_targets(timestamp, datapoints, blueprint['targets'])

    return len(messages)

def dispatch_datapoints_to_targets(timestamp, datapoints, targets):
    """
    Dispatch data points to given targets based on their grouping configuration.

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a dictionary of data points to be dispatched to given targets
    @param targets: a list of targets to receive retrieved data points
    """

    for target in targets:
        # A target can be configured to recieve all its datapoints from
        # various timeseries generators at once. This is helpful when
        # data points from the same time slot have to be used together (i.e.
        # to create a document with fields each tracking one or more of timeseries)
        if target.get('group_datapoints'):
            dispatch_group_datapoints(timestamp, datapoints, target)
        else:
            dispatch_single_datapoints(timestamp, datapoints, target)

def dispatch_single_datapoints(timestamp, datapoints, target):
    """
    Dispatch data points to given target one at a time based on target's slice sizes

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a dictionary of data points to be dispatched to given targets
    @param target: a target to receive retrieved data points
    """

    for generator_id in target['generators']:
        datapoint = datapoints[generator_id]
        # Slice up the datapoint (workload) for targets based on given slice sizes.
        # This is to both get around 5 min time limitations of Lambda invocations
        # and use parallelization to execute the datapoint (i.e. generate workload)
        # within a shorter time span when needed.
        datapoint_slices = slice_num(datapoint, target.get('slice_size', datapoint))

        # To gain maximum parallelization for executing datapoints slices on targets,
        # we delegate each slice-target processing to their own dedicated lambda run.
        for datapoint_slice in datapoint_slices:
            datapoint_slice_data = {
                'value': datapoint_slice,
                'generator_id': generator_id
            }
            lambda_self_invoke(get_target_payload(
                timestamp, [datapoint_slice_data], target))

def dispatch_group_datapoints(timestamp, datapoints, target):
    """
    Dispatch all data points to given target.

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a dictionary of data points to be dispatched to given targets
    @param target: a target to receive retrieved data points
    """

    datapoints_group = []
    for generator_id, datapoint_value in datapoints.iteritems():
        if generator_id in target['generators']:
            datapoints_group.append({
                'value': datapoint_value,
                'generator_id': generator_id
            })

    lambda_self_invoke(get_target_payload(
        timestamp, datapoints_group, target))

def get_target_payload(timestamp, datapoints, target):
    """
    Create the payload for dispatching data points to a target.

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a dictionary of data points to be dispatched to given targets
    @param target: a target to receive retrieved data points
    """

    simplified_target = target.copy()

    # Removing unnecessary and un-serializable fields
    if simplified_target.get('generators'):
        del simplified_target['generators']

    if simplified_target.get('client'):
        del simplified_target['client']

    return {
        'source': 'amazon-macie-activity-generator',
        'action': 'execute-datapoints',
        'timestamp': timestamp,
        'datapoints': datapoints,
        'target': simplified_target
    }

def set_target_client(target):
    """
    Set a boto client for a given target based on credentials explicitly
    specified (i.e. using IAM roles or explicit credentials) in its configuration
    or implicitly from the Lambda function's own credentials.

    @param target: a target to have its boto client set up
    """

    target_creds = None
    if target.get('role'):
        session_name = target['role'].get('session_name')
        if not session_name:
            session_name = 'amazon-macie-activity-generator' % get_rand_string(len = 8)

        if target['role'].get('external_id'):
            target_creds = sts_client.assume_role(
                RoleArn = target['role']['arn'],
                RoleSessionName = session_name,
                ExternalId = target['role'].get('external_id')
            )['Credentials']
        else:
            target_creds = sts_client.assume_role(
                RoleArn = target['role']['arn'],
                RoleSessionName = session_name
            )['Credentials']
    elif target.get('credentials'):
        target_creds = {
            'AccessKeyId': target['credentials']['access_key_id'],
            'SecretAccessKey': target['credentials']['secret_access_key'],
            'SessionToken': target['credentials'].get('session_token')
        }

    if target_creds:
        target['client'] = boto3.client(target['type'],
            aws_access_key_id = target_creds['AccessKeyId'],
            aws_secret_access_key = target_creds['SecretAccessKey'],
            aws_session_token = target_creds.get('SessionToken'))
    else:
        target['client'] = boto3.client(target['type'])

def execute_datapoints_on_target(timestamp, datapoints, target):
    """
    Call the local function corresponding to given target's type to execute data points.

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a list of data points to be transformed into actions on a target
    @param target: a target to execute data points
    """

    call_local_func(
        func_name = 'execute_datapoints_on_%s' % target['type'],
        func_args = {'timestamp': timestamp, 'datapoints': datapoints, 'target': target})

def execute_datapoints_on_cloudwatch(timestamp, datapoints, target):
    """
    Create CloudWatch custom metric data based on given data points.

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a list of data points to be transformed into actions on a target
    @param target: target CloudWatch custom metric
    """

    timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')

    metric_data_list = []
    for datapoint in datapoints:
        generator_shape = get_generator_shape(datapoint['generator_id'])
        metric_data_list.append({
            'MetricName': 'Timeseries',
            'Dimensions': [
                { 'Name': 'Shape', 'Value': generator_shape},
                { 'Name': 'Id', 'Value': datapoint['generator_id']}
             ],
             'Value': datapoint['value'],
             'Unit': 'Count',
             'Timestamp': timestamp
        })

    for metric_data_chunk in get_list_chunks(
        metric_data_list, CLOUDWATCH_METRIC_DATA_MEMBERS_MAX):
        target['client'].put_metric_data(
            Namespace = target['namespace'],
            MetricData = metric_data_chunk)

def execute_datapoints_on_lambda(timestamp, datapoints, target):
    """
    Pass data points to another AWS Lambda function as target

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a list of data points to be transformed into actions on a target
    @param target: target AWS Lambda function
    """

    payload = get_target_payload(timestamp, datapoints, target)

    target['client'].invoke(
        FunctionName = target['function'],
        InvocationType = 'Event',
        Payload = json.dumps(payload))

def select_bucket_objects(needed_keys_num, target):
    """
    Select a lis of objects to be read from the target S3 bucket.
    It will retrieve maximum of S3_LIST_OBJECTS_MAX real objects and
    fill out the rest with fake (non-existent) S3 objects keys.

    @param needed_keys_num: total number of S3 objects needed.
    @param target: target S3 bucket

    @return: a list of S3 objects keys
    """

    object_keys = []

    response = target['client'].list_objects_v2(
        Bucket = target['bucket'],
        Prefix = target.get('prefix', ''),
        MaxKeys = min(needed_keys_num, S3_LIST_OBJECTS_MAX))
    object_keys = response.get('Contents', [])

    if len(object_keys) < needed_keys_num:
        for _ in xrange(needed_keys_num - len(object_keys)):
            fake_key_name = '%sfake-object-%s' % (
                target.get('prefix', ''), get_rand_string(len = 8))
            object_keys.append({'Key': fake_key_name})

    return object_keys[:needed_keys_num]

def touch_bucket_object(object_keys, target):
    """
    Attempt to read a given S3 object from a target bucket and ignore failures.

    @param object_keys: a list of S3 objects keys to read
    @param target: target S3 bucket to read its S3 objects
    """

    object_key = object_keys[random.randint(0, len(object_keys) - 1)]['Key']
    try:
        target['client'].get_object(Bucket = target['bucket'], Key = object_key)
    except ClientError as ex:
        # Note: Ignore all boto errors as our object reads are best effort and
        # we don't want to interrupts the overall simulation due to isolated
        # failures. Especially in this context we expect errors as we might use
        # fake object names (= NoSuchKey errors).
        pass

def create_bucket_object(faker, target):
    """
    Create fake S3 objects in a given target S3 bucket. Based on the target's
    configuration, this function decides to make the objects private, public or
    randomly choose either. Also, the fake data is randomly distributed under
    prefixes named after their provider's name or under prefix of mixed.

    @param faker: a faker object to use for generating fake content
    @param target: target S3 bucket to put fake S3 objects
    """

    faker_providers = target.get('fake_types', ['sentence'])

    faker_provider = random.choice(faker_providers)
    faker_func = getattr(faker, faker_provider)

    # We create fake data objects in two groups of 1) prefixed with their
    # providers' name and 2) all mixed under the same prefix. The decision
    # for which group to create the object for is made randomly.
    if random.random() < 0.50:
        object_key = '%s%s/%s.fake' % (
            target.get('prefix',''), faker_provider, str(uuid.uuid4()))
    else:
        object_key = '%smixed/%s.fake' % (
            target.get('prefix',''), str(uuid.uuid4()))

    object_data = (
        'Sample Report - No identification of actual persons or '+
        'places is intended or should be inferred\r\n\r\n')

    for _ in xrange(target.get('fake_counts', 1)):
        object_data += '%s\r\n' % faker_func()

    content_types = target.get('content_types',
        [target.get('content_type', 'text/plain')])

    acls = target.get('acls', [target.get('acl', 'private')])

    target['client'].put_object(
        Bucket = target['bucket'],
        Key = object_key,
        Body = object_data,
        ContentType = random.choice(content_types),
        ACL = random.choice(acls))

def execute_datapoints_on_s3(timestamp, datapoints, target):
    """
    Execute a list of data points on a S3 bucket one at a time

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoints: a list of data points to be transformed into actions on a target
    @param target: target S3 bucket
    """

    for datapoint in datapoints:
        # No action for S3 target when datapoint is zero
        if datapoint:
            execute_datapoint_on_s3(timestamp, datapoint, target)

def execute_datapoint_on_s3(timestamp, datapoint, target):
    """
    Execute a single data point on a target bucket based on the S3 action
    specified in its configuration (i.e. get, put).

    @param timestamp: the time slot for retrieved data points from SQS queue
    @param datapoint: a data point to be transformed into actions on a target
    @param target: target S3 bucket
    """

    target_action = target.get('action', 'get')
    if target_action == 'get':
        object_keys = select_bucket_objects(
            needed_keys_num = datapoint['value'], target = target)
    elif target_action == 'put':
        faker = create_faker()

    for _ in xrange(int(datapoint['value'])):
        if target_action == 'get':
            touch_bucket_object(object_keys, target)
        elif target_action == 'put':
            create_bucket_object(faker, target)

def get_generator_shape(generator_id):
    """
    @param generator_id: identifier of a timeseries generator
    @return: shape of a timeseries generator from the blueprint.
    """

    for timeseries_generator in blueprint['generators']:
        if timeseries_generator['id'] == generator_id:
            return timeseries_generator['shape']

    return None

def build_blueprint():
    """
    Retrieves a blueprint from S3 and applies tranformation on it to
    reflect the configuration overrides for each timeseries generator.
    Any other blueprint adjustment (i.e. setting default S3 bucket for
    S3 targets) happens here.

    @return: a blueprint dictionary object
    """

    blueprint = json.loads(s3_client.get_object(
        Bucket = BLUEPRINT_S3_BUCKET_NAME,
        Key = BLUEPRINT_S3_OBJECT_KEY)['Body'].read())

    # Merge the common configurations into each generator's configuration,
    # and allow generator's configuration override the params in the commons.
    for timeseries_generator in blueprint['generators']:
        commons = blueprint['commons'].copy()
        if timeseries_generator.get('config'):
            commons.update(timeseries_generator['config'])
            timeseries_generator['config'] = commons
        else:
            timeseries_generator['config'] = commons

    # Update S3 targets with default bucket if needed
    for target in blueprint['targets']:
        if target['type'] == 's3' and not target.get('bucket'):
            target['bucket'] = DEFAULT_S3_BUCKET

    return blueprint

def lambda_self_invoke(event, type = 'Event'):
    """
    Invoke the current AWS Lambda function

    @param event: the payload to be passed to the Lambda function
    @param type: type of Lambda invocation (i.e. Event, RequestResponse)

    @return: result of Lambda function invocation
    """

    return lambda_client.invoke(
        FunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        InvocationType = type,
        Payload = json.dumps(event))

def main_thread(event, context):
    """
    Process Lambda function invocation based on given event payload.
    Currently, the function is either triggered by CloudWatch scheduled
    event or a self-invocation for dispatching data points to targets.

    @param event: payload data for the invocation
    @param context: runtime information about Lambda function
    """

    try:
        if event.get('source') == 'aws.events':
            if consume_datapoints(event['time']) == 0:
                # Refill the timeseries queue if it is empty
                produce_timeseries()
                # Try again to consume events from timeseries queue
                consume_datapoints(event['time'])
        elif event.get('source') == 'amazon-macie-activity-generator':
            if event.get('action') == 'execute-datapoints':
                execute_datapoints_on_target(
                    event['timestamp'], event['datapoints'], event['target'])
            else:
                logger.error('Unknown amazon-macie-activity-generator action requested:%s' % event.get('action'))
        else:
            logger.error('Unknown event source recieved:%s' % event.get('source'))
    except Exception, e:
        logger.exception('Failed to process lambda invocatio')

# Initiliaze all our global objects.
logger = logging.getLogger('amazon-macie-activity-generator')
logger.setLevel(logging.INFO)

sqs_client = boto3.client('sqs')
cw_client = boto3.client('cloudwatch')
s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')
sts_client = boto3.client('sts')

blueprint = build_blueprint()

def lambda_handler(event, context):
    """
    Delegate processing the Lambda function invocation to a dedicated thread.

    @param event: payload data for the invocation
    @param context: runtime information about Lambda function
    """

    logger.info('Processing lambda invocation:%s' % (json.dumps(event)))

    try:
        # We need to create custom boto3 clients for the targets in the main thread,
        # due to issues in boto3 for creating them in a multi-threaded environment.
        if (event.get('source') == 'amazon-macie-activity-generator' and
            event['target']['type'] in ['s3', 'cloudwatch', 'lambda']):
            set_target_client(event['target'])

        # amazon-macie-activity-generator works on the best effort mechanism and does not attempt
        # to go back in time and replay what has been failed. This is mainly
        # due to how datapoints are expected to be executed on targets at specifc
        # time slots (and of course lack of access to a time machine). Hence, we
        # do everything in a separate thread to avoid any exceptions or timeouts
        # trigger a lambda re-invocation and duplicate or out of sync execution of
        # datapoints on targets.
        t = Thread(target = main_thread, args = [event, context])
        t.daemon = True
        t.start()

        t.join(timeout = context.get_remaining_time_in_millis()/1000 - 10)
        if t.is_alive():
            logger.error('Processing lambda invocation timed out.')
    except Exception, e:
        # Even in this case we don't want Lambda retries and we rather the next
        # next CloudWatch event trigger to help deal with any transient errors.
        logger.exception('Lambda pre-thread initilization failure')
