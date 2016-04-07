import argparse
import os
import yaml

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
        self.weights = None
        self.sender_profile_size = 0
        self.data_matrix_size = 0
        self.model_path_out = './model'
        self.summary_path_out = './summary'

        #Generator and Classifier
        self.feature_generator = None
        self.classifier = None

    def parse_args(self):
        """
        Parses command line arguments.
        """
        parser = argparse.ArgumentParser(description='Mange spear fishing detector.')
        parser.add_argument('--all',
                            action='store_true',
                            help=('Generate and serialize data matrix, test, matrix, and ML model, then run ML model on test matrix'))
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
            'training_filename',
            'test_filename',
            'sender_profile_size',
            'data_matrix_size',
            'test_matrix_size',
            'model_path_out',
            'result_path_out',
            'weights',
            'detectors',
        ]

        try:
            for key in expected_config_keys:
                setattr(self, key, config[key])
        except KeyError:
            print("Configuration file missing entry")
            raise

        self.root_dir = os.path.abspath(self.root_dir)

    def generate_features(self):
        feature_generator = FeatureGenerator()
        
        feature_generator.phishing_filename = ''
        feature_generator.regular_filename = self.training_filename
        feature_generator.test_filename = self.test_filename
        feature_generator.sender_profile_size = self.sender_profile_size
        feature_generator.data_matrix_size = self.data_matrix_size
        feature_generator.test_matrix_size = self.test_matrix_size
        feature_generator.do_generate_data_matrix = self.generate_data_matrix
        feature_generator.do_generate_test_matrix = self.generate_test_matrix

        dir_to_generate = []

        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            run_training = False
            run_test = False

            if self.generate_data_matrix and self.training_filename in filenames:
                run_training = True
            if self.generate_test_matrix and self.test_filename in filenames:
                run_test = True

            if run_test or run_training:
                dir_to_generate.append(dirpath)

        for directory in dir_to_generate:
            os.chdir(directory)
            feature_generator.run()
            os.chdir(self.root_dir)

    def generate_model(self):
        pass

    def execute(self):
        self.parse_config()
        self.parse_args()

        if self.generate_data_matrix or self.generate_test_matrix:
            self.generate_features()

if __name__ == '__main__':
    detector = PhishDetector()
    detector.execute()
