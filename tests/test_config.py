import pytest
import json
import os
import tempfile
from config.settings import Config, get_config


class TestConfig:

    def test_config_default_values(self):
        config = Config()
        assert config.timeout == 10
        assert config.max_retries == 2
        assert config.rate_limit_requests == 10
        assert config.verbose is False
        assert config.http_method == 'POST'
        assert config.language == 'en'

    def test_config_custom_values(self):
        config = Config(
            timeout=30,
            max_retries=5,
            verbose=True,
            http_method='GET'
        )
        assert config.timeout == 30
        assert config.max_retries == 5
        assert config.verbose is True
        assert config.http_method == 'GET'

    def test_config_from_dict(self):
        data = {
            'timeout': 20,
            'max_retries': 3,
            'verbose': True
        }
        config = Config.from_dict(data)
        assert config.timeout == 20
        assert config.max_retries == 3
        assert config.verbose is True

    def test_config_from_dict_invalid_fields(self):
        data = {
            'timeout': 20,
            'invalid_field': 'should be ignored'
        }
        config = Config.from_dict(data)
        assert config.timeout == 20
        assert not hasattr(config, 'invalid_field')

    def test_config_to_dict(self):
        config = Config(timeout=15, verbose=True)
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert config_dict['timeout'] == 15
        assert config_dict['verbose'] is True

    def test_config_from_file(self):
        config_data = {
            'timeout': 25,
            'max_retries': 4,
            'verbose': True
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            config = Config.from_file(temp_path)
            assert config.timeout == 25
            assert config.max_retries == 4
            assert config.verbose is True
        finally:
            os.unlink(temp_path)

    def test_config_from_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            Config.from_file('nonexistent_config.json')

    def test_config_from_file_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ invalid json }')
            temp_path = f.name

        try:
            with pytest.raises(ValueError):
                Config.from_file(temp_path)
        finally:
            os.unlink(temp_path)

    def test_config_save_to_file(self):
        config = Config(timeout=30, verbose=True)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            config.save_to_file(temp_path)
            assert os.path.exists(temp_path)

            with open(temp_path, 'r') as f:
                loaded_data = json.load(f)
                assert loaded_data['timeout'] == 30
                assert loaded_data['verbose'] is True
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_config_merge_cli_args(self):
        config = Config(timeout=10, verbose=False)
        cli_args = {
            'timeout': 20,
            'verbose': True
        }
        merged = config.merge_cli_args(cli_args)
        assert merged.timeout == 20
        assert merged.verbose is True

        assert config.timeout == 10
        assert config.verbose is False

    def test_get_config_default(self):
        config = get_config()
        assert isinstance(config, Config)
        assert config.timeout == 10

    def test_get_config_with_cli_args(self):
        cli_args = {
            'timeout': 30,
            'verbose': True
        }
        config = get_config(cli_args=cli_args)
        assert config.timeout == 30
        assert config.verbose is True

    def test_get_config_with_file(self):
        config_data = {
            'timeout': 40,
            'max_retries': 5
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            config = get_config(config_file=temp_path)
            assert config.timeout == 40
            assert config.max_retries == 5
        finally:
            os.unlink(temp_path)

    def test_get_config_file_and_cli_args(self):
        config_data = {
            'timeout': 40,
            'verbose': False
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            cli_args = {
                'timeout': 50,
                'verbose': True
            }
            config = get_config(cli_args=cli_args, config_file=temp_path)

            assert config.timeout == 50
            assert config.verbose is True
        finally:
            os.unlink(temp_path)
