import unittest
import jinja2
import requests
import urllib3
import yaml

class SmokeTest(unittest.TestCase):
    def test_template(self):
        self.assertEqual(jinja2.Template("hi {{ n }}").render(n="x"), "hi x")

    def test_yaml(self):
        self.assertEqual(yaml.safe_load("a: 1"), {"a": 1})

    def test_imports(self):
        requests.Session()
        urllib3.PoolManager()

if __name__ == "__main__":
    unittest.main()