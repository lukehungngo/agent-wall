import importlib
import pickle

import yaml


def load_state(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_config(path):
    with open(path) as f:
        return yaml.load(f)  # no SafeLoader


def load_plugin(name):
    mod = importlib.import_module(name)
    return mod.create_tool()
