import logging
import os
import subprocess
import requests
import pwnagotchi.plugins as plugins
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts


class HashcatServer(plugins.Plugin):
    __author__ = 'liquidmind@me.com'
    __version__ = '1.0.10'
    __license__ = 'GPL3'
    __description__ = 'Converts pcap files to .22000 format and uploads them to a server when internet is available. Also checks and displays available jobs.'

    def __init__(self):
        self.upload_queue = []

    def on_loaded(self):
        self.server_ip = self.options['server_ip']
        self.server_port = self.options['server_port']
        self.api_url = f'http://{self.server_ip}:{self.server_port}/api/jobs'
        self.job_ids = {}  # Initialize job_ids to track jobs
        logging.basicConfig(level=logging.INFO)  # Set up logging
        logging.info("HashcatServer plugin loaded with options: %s" % self.options)

    def _convert_to_22000(self, pcap_file):
        hcx_file = pcap_file.replace('.pcap', '.22000')
        cmd = ['hcxpcapngtool', '-o', hcx_file, pcap_file]
        try:
            logging.debug(f"Running command: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            logging.info(f"Converted {pcap_file} to {hcx_file}")
            return hcx_file
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to convert {pcap_file} to .22000: {e}")
            return None

    def _upload_to_server(self, agent, hcx_file):
        url = f"http://{self.options['server_ip']}:{self.options['server_port']}/upload"

        # Verify file exists and is non-empty
        if not os.path.exists(hcx_file) or os.path.getsize(hcx_file) == 0:
            logging.error(f"File {hcx_file} does not exist or is empty, skipping upload.")
            return False

        # Construct the curl command
        curl_command = [
            'curl',
            '-X', 'POST',  # HTTP POST request
            url,
            '-F', f"capture=@{hcx_file}"  # File upload using the form field 'capture'
        ]

        try:
            # Use subprocess to execute the curl command
            process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            # Log the raw output
            logging.info(f"Curl output: {stdout.strip()}")
            if stderr:
                logging.error(f"Curl error: {stderr.strip()}")

            # Check for success based on curl's output
            if process.returncode == 0:
                if '"status":"success"' in stdout:
                    job_id = self._extract_job_id(stdout)  # Extract job ID from the response
                    if job_id:
                        self.job_ids[job_id] = hcx_file
                        message = f"Uploaded {hcx_file} and got job ID {job_id}"
                        logging.info(message)
                        agent.view.set('status', message)
                        return job_id
                    else:
                        logging.error(f"Failed to extract job ID from the server response for {hcx_file}")
                        return False
                else:
                    logging.error(f"Upload failed or server returned an error: {stdout.strip()}")
                    return False
            else:
                logging.error(f"Curl command failed with return code {process.returncode}")
                return False

        except Exception as e:
            logging.error(f"Exception while uploading {hcx_file}: {e}")
            return False

    def _extract_job_id(self, stdout):
        # This method extracts the job ID from the server's JSON response
        import json
        try:
            response = json.loads(stdout)
            return response.get('job_id')
        except json.JSONDecodeError:
            logging.error("Failed to parse JSON response from server.")
            return None

    def _fetch_jobs(self):
        try:
            logging.debug(f"Fetching jobs from {self.api_url}")
            response = requests.get(self.api_url)
            if response.status_code == 200:
                jobs = response.json()
                logging.info(f"Retrieved jobs: {jobs}")
                return jobs
            else:
                logging.error(f"Failed to retrieve jobs. Status code: {response.status_code}")
                return None
        except requests.RequestException as e:
            logging.error(f"Error fetching jobs: {e}")
            return None

    def on_handshake(self, agent, filename, access_point, client_station):
        logging.info(f"Captured handshake: {filename}")
        hcx_file = self._convert_to_22000(filename)
        if hcx_file:
            self.upload_queue.append(hcx_file)
            logging.info(f"Queued {hcx_file} for upload when internet is available")

    def on_internet_available(self, agent):
        if self.upload_queue:
            logging.info("Internet available, uploading queued files...")
            for hcx_file in self.upload_queue[:]:  # Create a copy of the list to avoid modifying during iteration
                if self._upload_to_server(agent, hcx_file):  # Pass 'agent' to '_upload_to_server'
                    self.upload_queue.remove(hcx_file)
                else:
                    logging.error(f"Failed to upload {hcx_file}, re-queuing for next attempt")

    def on_ui_update(self, ui):
        jobs = self._fetch_jobs()
        if jobs:
            total_jobs = len(jobs)
            current_job = None

            # Find the current job with ongoing progress
            for job in jobs:
                if self.job_ids.get(job['id']):
                    job_status = self.job_ids[job['id']]['status']
                    if job_status == 'running':
                        current_job = job
                        break

            if current_job:
                progress = self.job_ids[current_job['id']]['progress']
                job_number = list(self.job_ids.keys()).index(current_job['id']) + 1
                ui.set('hashcat', f"Progress: {progress}")
            else:
                ui.set('hashcat', "No jobs")
        else:
            ui.set('hashcat', "No jobs")

    def on_unload(self, ui):
        with ui._lock:
            try:
                ui.remove_element("hashcat")
                logging.info(f"[{self.__class__.__name__}] plugin unloaded")
            except Exception as e:
                logging.error(f"[{self.__class__.__name__}] unload: %s" % e)

    def on_ui_setup(self, ui):
        ui.add_element(
            "hashcat",
            LabeledValue(
                color=BLACK,
                label="hashcat",
                value="",
                position=(180, 130),
                label_font=fonts.Bold,
                text_font=fonts.Medium,
            ),
        )
