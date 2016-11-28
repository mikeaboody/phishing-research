import argparse
import datetime as dt
import logging
from multiprocessing import Pool
import os
import time
import traceback

import yaml

from classify import Classify
from detector import Detector
import feature_classes as fc
from generate_features import FeatureGenerator
from lookup import Lookup
from memtest import MemTracker
import logs

progress_logger = logging.getLogger('spear_phishing.progress')
memory_logger = logging.getLogger('spear_phishing.memory')

class PhishDetector(object):

    def __init__(self):
        #Flag Configurations
        self.generate_data_matrix = False
        self.generate_test_matrix = False
        self.generate_model = False
        self.classify = False
        self.config_path = 'config.yaml'

        #Config File Configurations
        self.root_dir = None
        self.filename = None
        self.weights = None
        self.sender_profile_percentage = 0
        self.data_matrix_percentage = 0
        self.test_matrix_percentage = 0
        self.emails_threshold = 1000
        self.results_size = 10
        self.model_path_out = './model'
        self.result_path_out = './summary'
        self.detectors = None
        self.parallel = None

        #Generator and Classifier
        self.classifier = None

        self.parse_config()
        self.parse_args()


    def parse_args(self):
        """
        Parses command line arguments.
        """
        parser = argparse.ArgumentParser(description='Mange spear fishing detector.')
        parser.add_argument('--all',
                            action='store_true',
                            help=('Generate and serialize data matrix, test matrix, and ML model, then run ML model on test matrix'))
        parser.add_argument('--gen_all',
                            action='store_true',
                            help=('Generate and serialize data matrix, test matrix, and ML model'))
        parser.add_argument('--gen_data',
                            action='store_true',
                            help=('Generate and serialize data matrix'))
        parser.add_argument('--gen_test',
                            action='store_true',
                            help=('Generate and serialize test matrix'))
        parser.add_argument('--gen_model',
                            action='store_true',
                            help=('Generate and serialize ML model'))
        parser.add_argument('--classify',
                            action='store_true',
                            help=('Run ML model on test matrix'))
        parser.add_argument('--debug_training',
                            action='store_true',
                            help=('Debug the training step of the pipeline.'))
        parser.add_argument('--mbox',
                            action='store_true',
                            help=('Use emails from mbox rather than pcaps'))
        
        args = parser.parse_args()

        run = False
        self.debug_training = False
        if args.all:
            self.generate_data_matrix = True
            self.generate_test_matrix = True
            self.generate_model = True
            self.classify = True
            run = True
        if args.gen_all:
            self.generate_data_matrix = True
            self.generate_test_matrix = True
            self.generate_model = True
            run = True
        if args.gen_data:
            self.generate_data_matrix = True
            run = True
        if args.gen_test:
            self.generate_test_matrix = True
            run = True
        if args.gen_model:
            self.generate_model = True
            run = True
        if args.classify:
            self.classify = True
            run = True
        if args.debug_training:
            self.generate_data_matrix = True
            self.generate_test_matrix = True
            self.generate_model = True
            self.classify = True
            self.debug_training = True
            run = True


        if not run:
            parser.error('You must run with at least one flag')

    def parse_config(self):
        """
        Parses configuration file. Assumes configuration is in same directory as this script.
        """
        try:
            stream = file(self.config_path, 'r')
        except IOError:
            progress_logger.exception("Could not find yaml configuration file.")
            raise

        config = yaml.load(stream)
        
        expected_config_keys = [
            'root_dir',
            'regular_filename',
            'phish_filename',
            'sender_profile_percentage',
            'data_matrix_percentage',
            'test_matrix_percentage',
            'use_name_in_from',
            'model_path_out',
            'result_path_out',
            'weights',
            'detectors',
            'emails_threshold',
            'batch_threading_size',
            'offline',
            'results_size',
            'parallel',
            'num_threads',
            'logging_interval',
            'memlog_gen_features_frequency',
            'memlog_classify_frequency'
        ]

        try:
            for key in expected_config_keys:
                setattr(self, key, config[key])
        except KeyError:
            progress_logger.exception("Configuration file missing entry")
            raise

        detectors = []
        for detector, val in self.detectors.items():
            if val == 1:
                detectors.append(getattr(globals()['fc'], detector))

        self.detectors = detectors
        self.root_dir = os.path.abspath(self.root_dir)
        Lookup.initialize(offline=self.offline)

    def prep_features(self, directory):   
        regular_path = os.path.join(directory, self.regular_filename)
        phish_path = os.path.join(directory, self.phish_filename)

        feature_generator = FeatureGenerator(directory,
                                             regular_path,
                                             phish_path,
                                             self.sender_profile_percentage,
                                             self.data_matrix_percentage,
                                             self.test_matrix_percentage,
                                             self.detectors
                                            )

        feature_generator.do_generate_data_matrix = self.generate_data_matrix
        feature_generator.do_generate_test_matrix = self.generate_test_matrix
        return feature_generator


    def generate_features(self):
        if self.use_name_in_from != 0:
            Detector.USE_NAME = True

        dir_to_generate = []

        progress_logger.info('Starting directory aggregation in feature generation.')
        start_time = time.time()
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            if ((self.generate_data_matrix and self.regular_filename in filenames and self.phish_filename in filenames)
                or (self.generate_test_matrix and self.regular_filename in filenames)):
                dir_to_generate.append(dirpath)
                logs.Watchdog.reset()
        end_time = time.time()
        min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
        progress_logger.info('Finished directory aggregation in feature generation in {} minutes, {} seconds'.format(min_elapsed, sec_elapsed))
        
        BATCH_SIZE = self.batch_threading_size
        if self.parallel:
            progress_logger.info('Starting feature generation with {} threads in parallel with batch size {}...'.format(self.num_threads, BATCH_SIZE))
            start_time = time.time()
            feature_generators = []
            for directory in dir_to_generate:
                feature_generator = self.prep_features(directory)
                feature_generators.append(feature_generator)
                if len(feature_generators) == BATCH_SIZE:
                    p = Pool(self.num_threads)
                    p.map(run_generator, feature_generators)
                    p.close()
                    p.join()
                    feature_generators = []
            if len(feature_generators) > 0:
                p = Pool(self.num_threads)
                p.map(run_generator, feature_generators)
                p.close()
                p.join()
            end_time = time.time()
            min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
            progress_logger.info('Finished feature generation in {} minutes, {} seconds.'.format(min_elapsed, sec_elapsed))
        else:
            progress_logger.info('Starting feature generation serially for {} directories'.format(len(dir_to_generate)))
            start_time = time.time()
            last_logged_time = start_time
            dir_count = 0
            end_of_last_memory_track = dt.datetime.now()
            for directory in dir_to_generate:
                dir_count += 1
                logs.context = {'feature gen': dir_count}
                curr_time = time.time()
                if (curr_time - last_logged_time) > self.logging_interval * 60:
                    progress_logger.info('Processing directory #{} of {}'.format(dir_count, len(dir_to_generate)))
                    progress_logger.info('Feature generation has run for {} minutes'.format(int((curr_time - start_time) / 60)))
                    last_logged_time = curr_time
                feature_generator = self.prep_features(directory)
                feature_generator.run()
                logs.Watchdog.reset()
                now = dt.datetime.now()
                time_elapsed = now - end_of_last_memory_track
                minutes_elapsed = time_elapsed.seconds / 60.0
                if minutes_elapsed > self.memlog_gen_features_frequency:
                    MemTracker.logMemory('After generating features for {}th sender'.format(dir_count))
                    end_of_last_memory_track = dt.datetime.now()
                logs.context = {}
            end_time = time.time()
            min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
            progress_logger.info('Finished feature generation in {} minutes, {} seconds.'.format(min_elapsed, sec_elapsed))

    def generate_model_output(self):
        self.classifier = Classify(self.weights,
                                   self.root_dir,
                                   self.emails_threshold,
                                   self.results_size,
                                   results_dir=self.result_path_out,
                                   serial_path=self.model_path_out,
                                   memlog_freq=self.memlog_classify_frequency,
                                   debug_training=self.debug_training)
        logs.Watchdog.reset()
        self.classifier.generate_training()
        logs.Watchdog.reset()
        self.classifier.train_clf()
        logs.Watchdog.reset()
        self.classifier.cross_validate()
        logs.Watchdog.reset()
        self.classifier.test_and_report()
        logs.Watchdog.reset()


    def execute(self):
        start_time = time.time()
        MemTracker.initialize(memory_logger)
        logs.Watchdog.initialize()
        logs.context = {'phase': 'generate_features'}
        if self.generate_data_matrix or self.generate_test_matrix:
            self.generate_features()
        logs.context = {}
        MemTracker.logMemory("After generating features/Before generating model")
        logs.context = {'phase': 'generate_model_output'}
        if self.generate_model:
            self.generate_model_output()
        logs.context = {}
        MemTracker.logMemory("After generating model")
        end_time = time.time()
        min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
        progress_logger.info("Phish Detector took {} minutes, {} seconds to run.".format(min_elapsed, sec_elapsed))
        logs.RateLimitedLog.flushall()

def run_generator(generator):
    #Load offline info for Lookup class
    try:
        generator.run()
        Lookup.writeStatistics()
    except:
        traceback.print_exc()
        raise RuntimeError("thread raised an error")
    
def main():
    detector = PhishDetector()
    detector.execute()
