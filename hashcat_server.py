import logging
import os
import subprocess
import requests
import pwnagotchi.plugins as plugins
import time


class HandshakeUploader(plugins.Plugin):
    __author__ = 'liquidmind@me.com'
    __version__ = '0.1.0'
    __license__ = 'GPL3'
    __description__ = 'Converts pcap files to .22000 format, uploads them to a server, and displays upload progress.'

    def __init__(self):
        super().__init__()
        self.upload_queue = []
        self.job_ids = {}  # Dictionary to store job IDs and their associated files
        self.status_check_interval = 30  # Interval in seconds to check job status

    def _convert_to_22000(self, pcap_file):
        hcx_file = pcap_file.replace('.pcap', '.22000')
        cmd = ['hcxpcaptool', '-o', hcx_file, pcap_file]
        try:
            subprocess.run(cmd, check=True)
            logging.info(f"Converted {pcap_file} to {hcx_file}")
            return hcx_file
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to convert {pcap_file} to .22000: {e}")
            return None

    def _upload_to_server(self, agent, hcx_file):
        url = f"http://{self.options['server_ip']}:{self.options['server_port']}/upload"
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
                    message = f"Failed to get job ID from server for {hcx_file}"
                    logging.error(message)
                    agent.view.set('status', message)
                    return None
            else:
                message = f"Failed to upload {hcx_file}: {response.status_code}"
                logging.error(message)
                agent.view.set('status', message)
                return None
        except requests.RequestException as e:
            message = f"Error uploading {hcx_file}: {e}"
            logging.error(message)
            agent.view.set('status', message)
            return None

    def _check_job_status(self, agent, job_id):
        url = f"http://{self.options['server_ip']}:{self.options['server_port']}/status/{job_id}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                status_info = response.json()
                status = status_info.get("status")
                progress = status_info.get("progress")
                message = status_info.get("message")
                if status:
                    status_message = f"Job ID {job_id} status: {status}, Progress: {progress}"
                    logging.info(status_message)
                    agent.view.set('status', status_message)
                    if status == "completed" or status == "error":
                        self.job_ids.pop(job_id, None)  # Remove completed or errored jobs
            else:
                message = f"Failed to get status for job ID {job_id}: {response.status_code}"
                logging.error(message)
                agent.view.set('status', message)
        except requests.RequestException as e:
            message = f"Error checking status for job ID {job_id}: {e}"
            logging.error(message)
            agent.view.set('status', message)

    def on_handshake(self, agent, filename, access_point, client_station):
        message = f"Captured handshake: {filename}"
        logging.info(message)
        agent.view.set('status', message)
        hcx_file = self._convert_to_22000(filename)
        if hcx_file:
            self.upload_queue.append(hcx_file)
            message = f"Queued {hcx_file} for upload when internet is available"
            logging.info(message)
            agent.view.set('status', message)

    def on_internet_available(self, agent):
        if self.upload_queue:
            logging.info("Internet available, uploading queued files...")
            agent.view.set('status', "Internet available, uploading queued files...")
            for hcx_file in self.upload_queue[:]:  # Create a copy of the list
                job_id = self._upload_to_server(agent, hcx_file)
                if job_id:
                    self.upload_queue.remove(hcx_file)

    def on_loaded(self):
        logging.info("HandshakeUploader plugin loaded with options: %s" % self.options)
        agent.view.set('status', "HandshakeUploader plugin loaded")
        self._start_periodic_status_check()

    def on_unload(self, agent):
        logging.info("HandshakeUploader plugin unloaded")
        agent.view.set('status', "HandshakeUploader plugin unloaded")

    def _start_periodic_status_check(self):
        def check_status():
            while True:
                if self.job_ids:
                    for job_id in list(self.job_ids.keys()):
                        self._check_job_status(None, job_id)  # Passing None as agent, adjust if needed
                time.sleep(self.status_check_interval)

        import threading
        status_thread = threading.Thread(target=check_status, daemon=True)
        status_thread.start()
