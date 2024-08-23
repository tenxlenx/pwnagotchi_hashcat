import logging
import os
import subprocess
import requests
import pwnagotchi.plugins as plugins

class HashcatServer(plugins.Plugin):
    __author__ = 'liquidmind@me.com'
    __version__ = '1.0.5'
    __license__ = 'GPL3'
    __description__ = 'Converts pcap files to .22000 format and uploads them to a server when internet is available. Also checks and displays available jobs.'


    def __init__(self):
        self.upload_queue = []
    
    def on_loaded(self):
        self.server_ip = self.options['server_ip']
        self.server_port = self.options['server_port']
        self.api_url =  f'http://{self.server_ip}:{self.server_port}/api/jobs'
        logging.basicConfig(level=logging.INFO)  # Set up logging
        logging.info("hashcat server loaded with options: %s" % self.options)
        
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

        files = {'capture': open(hcx_file, 'rb')}
        try:
            response = requests.post(url, files=files)
            if response.status_code == 200:
                job_id = response.json().get("job_id")
                if job_id:
                    self.job_ids[job_id] = hcx_file
                    message = f"Uploaded {hcx_file} and got job ID {job_id}"
                    logging.info(message)
                    agent.view.set('status', message)
                    return job_id
                else:
                    logging.error(f"Failed to get job ID from server for {hcx_file}")
                    return False
            else:
                logging.error(f"Failed to upload {hcx_file}. Status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
            return False
        finally:
            files['capture'].close()

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
                if self._upload_to_server(hcx_file):
                    self.upload_queue.remove(hcx_file)
                else:
                    logging.error(f"Failed to upload {hcx_file}, re-queuing for next attempt")

    def on_ui_update(self, agent):
        jobs = self._fetch_jobs()
        if jobs:
            job_list = "\n".join([f"- {job['title']} (ID: {job['id']})" for job in jobs])
            agent.view.set('status', f"Current Jobs:\n{job_list}")
        else:
            agent.view.set('status', "Failed to retrieve jobs")
            
    def on_unload(self, agent):
        logging.info("hashcat server unloaded")
