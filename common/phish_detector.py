import argparse
import os
import time
import yaml
import feature_classes as fc
from classify import Classify  

from multiprocessing import Pool
from generate_features import FeatureGenerator

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
        self.parallel = True

        #Generator and Classifier
        self.feature_generators = []
        self.classifier = None


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
        parser.add_argument('--no_parallel',
                            action='store_true',
                            help=('Generate features for matrices serially.'))
        
        args = parser.parse_args()

        run = False
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

        if args.no_parallel:
            self.parallel = False

        if not run:
            parser.error('You must run with at least one flag')

    def parse_config(self):
        """
        Parses configuration file. Assumes configuration is in same directory as this script.
        """
        try:
            stream = file(self.config_path, 'r')
        except IOError:
            print("Could not find yaml configuration file.")
            raise

        config = yaml.load(stream)
        
        expected_config_keys = [
            'root_dir',
            'regular_filename',
            'phish_filename',
            'sender_profile_percentage',
            'data_matrix_percentage',
            'test_matrix_percentage',
            'model_path_out',
            'result_path_out',
            'weights',
            'detectors',
            'emails_threshold',
            'results_size',
        ]

        try:
            for key in expected_config_keys:
                setattr(self, key, config[key])
        except KeyError:
            print("Configuration file missing entry")
            raise

        detectors = []
        for detector, val in self.detectors.items():
            if val == 1:
                detectors.append(getattr(globals()['fc'], detector))

        self.detectors = detectors
        self.root_dir = os.path.abspath(self.root_dir)

    def prep_features(self):
        dir_to_generate = []

        for dirpath, dirnames, filenames in os.walk(self.root_dir):

            if ((self.generate_data_matrix and self.regular_filename in filenames and self.phish_filename in filenames)
                or (self.generate_test_matrix and self.regular_filename in filenames)):

                dir_to_generate.append(dirpath)

        for directory in dir_to_generate:
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

            self.feature_generators.append(feature_generator)

    def generate_features(self):
        self.prep_features()
        
        if self.parallel:
            p = Pool(5)
            p.map(run_generator, self.feature_generators)
            p.close()
            p.join()
        else:
            for generator in self.feature_generators:
                generator.run()

    def generate_model_output(self):
        self.classifier = Classify(self.weights, self.root_dir, self.emails_threshold, self.results_size, serial_path=self.model_path_out)
        self.classifier.generate_training()
        self.classifier.train_clf()
        self.classifier.test_and_report()


    def execute(self):
        self.parse_config()
        self.parse_args()
        
        start_time = time.time()

        if self.generate_data_matrix or self.generate_test_matrix:
            self.generate_features()
        if self.generate_model:
            self.generate_model_output()

        end_time = time.time()

        print ("Phish Detector took {} seconds to run.".format(int(end_time - start_time)))

def run_generator(generator):
    generator.run()

if __name__ == '__main__':
    detector = PhishDetector()
    detector.execute()
    
