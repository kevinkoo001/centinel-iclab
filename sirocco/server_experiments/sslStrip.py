import requests

from centinel.experiment import Experiment
from utils import logger


class SSLStripExperiment(Experiment):
    name = "sslStrip"

    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []

    def run(self):
        for line in self.input_file:
            site = line.strip()
            self.ssl_strip_test(site)

    def ssl_strip_test(self, site):
        result = {
            "site": site,
        }

        logger.log("i", "Checking {0} for SSL stripping".format(site))
        r = requests.get('http://' + site, allow_redirects=False)
        result["headers"] = dict(r.headers)
        result["status"] = r.status_code
        # if the status code is not 3xx or the redirect location does
        # not contain https, then this is a bad site
        result["success"] = True
        if (r.status_code > 399) or (r.status_code < 300):
            result["success"] = False
        elif (("location" in r.headers) and
              ("https" not in r.headers["location"])):
            result["success"] = False
        self.results.append(result)
