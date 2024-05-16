# !/usr/bin/env python3
# https://github.com/jonviveiros/Infrastructure-Code

# DESCRIPTION
# The goal is to pull output from various SSH devices. Threading and device autodetection
# are leveraged to gather relevant information. Device_type is recognized for supported
# devices to ensure only relevant commands are used.
# Authentication via prompt

import re
import os
import csv
# import json
# import requests
import signal
import sys
import threading
from time import sleep
from getpass import getpass
from datetime import datetime, date
from queue import Queue
from paramiko.ssh_exception import NoValidConnectionsError, AuthenticationException

from netmiko import Netmiko, NetMikoTimeoutException, NetMikoAuthenticationException
from netmiko import SSHDetect

# These capture errors relating to hitting ctrl+C
signal.signal(signal.SIGINT, signal.SIG_DFL)  # KeyboardInterrupt: Ctrl-C

# Get username/password
username = input('Enter the username: ')
password = getpass('Enter the password: ')
secret = password
ip_addrs = []

# Create files
ipfile = input('Enter the IP Addresses filename or press [Enter] to use the default of ips.txt: ')
csvfile = ("IPtoDNS output/parsed_data " + str(date.today()) + '.csv')


if ipfile == '':
    with open('ips.txt', encoding='UTF-8') as ip_addrs_file:
        for line in ip_addrs_file:
            if re.match(r'\d', line[0]):
                ip_addrs.append(line.strip())
            if re.match(r'[a-zA-Z]', line[0]):
                ip_addrs.append(line.strip())
            else:
                continue
else:
    with open(ipfile, encoding='UTF-8') as ip_addrs_file:
        for line in ip_addrs_file:
            if re.match(r'\d', line[0]):
                ip_addrs.append(line.strip())
            if re.match(r'[a-zA-Z]', line[0]):
                ip_addrs.append(line.strip())
            else:
                continue

cmd = 'show ip int brief | e una'

# Define the output folder
os.makedirs('IPtoDNS output', exist_ok=True)

# Set up thread count for number of threads to spin up.
threads = 10
# This sets up the queue
enclosure_queue = Queue()
# Set up thread lock so that only one thread prints at a time
print_lock = threading.Lock()

print('*****\nInitiating IP to DNS process ...\n*****')

# Function used in threads to connect to devices, passing in the thread # and queue


def deviceconnector(i, q):
    # This while loop runs indefinitely and grabs IP addresses from the queue and processes them
    # Loop will be blocked and wait if "ip = q.get()" is empty
    while True:

        ip = q.get()
        with print_lock:
            print('Th{}/{}: Acquired IP:  {}'.format(i+1, threads, ip))

        # Create files
        errorfile = open("IPtoDNS output/IPtoDNS errors " + str(date.today()) + ".txt", 'a')
        csvfile = open("IPtoDNS output/parsed_data " + str(date.today()) + '.csv', "a", newline='')
        rawoutputfile = open("IPtoDNS output/IPtoDNS raw output " + str(date.today()) + ".txt", 'a')
        infoblox_csv = open("IPtoDNS output/infoblox_import " + str(date.today()) + ".csv", 'a')

        # device_dict is copied over to net_connect
        device_dict = {
            'host': ip,
            'username': username,
            'password': password,
            'secret': secret,
            'device_type': 'autodetect',
            'banner_timeout': 60,
            'conn_timeout': 60
            # Gather session output logs - TESTING ONLY
            # ,
            # 'session_log': 'session_output.txt'
        }

        # device type autodetect based on netmiko
        try:
            auto_device_dict = SSHDetect(**device_dict)
            device_os = auto_device_dict.autodetect()
            # Validate device type returned (Testing only)
            # print(('===== {} =====\n===== {} ====='.format(device_os, auto_device_dict.potential_matches))

            # Update device_dict device_type from 'autodetect' to the detected OS
            if device_os is None:
                print('Th{}/{}: {} returned unsupported device_type of {}\n'.format(i + 1, threads, device_dict['host'],
                      device_os))
                device_dict['device_type'] = 'autodetect'
            else:
                device_dict['device_type'] = device_os

            # Connect to the device, and print out auth or timeout errors
            net_connect = Netmiko(**device_dict)
            print('Th{}/{}: Connecting to: {} ({})'.format(i+1, threads, net_connect.host, net_connect.device_type))
        except NetMikoTimeoutException:
            with print_lock:
                print('Th{}/{}: ERROR: Connection to {} timed-out. \n'.format(i+1, threads, ip))
                errorfile.write('[{}] {} ERROR: Connection timed-out. \n'.format(datetime.now().strftime('%H:%M:%S'), ip))
            q.task_done()
            break
        except (NetMikoAuthenticationException, AuthenticationException):
            with print_lock:
                print('Th{}/{}: ERROR: Authentication failed for {}. Stopping thread. \n'.format(i+1, threads, ip))
                errorfile.write('[{}] {} ERROR: Authentication failed. \n'.format(datetime.now().strftime('%H:%M:%S'), ip))
            q.task_done()
            break
        except NoValidConnectionsError:
            with print_lock:
                print('Th{}/{}: ERROR: No Connections available for device {}. \n'.format(i+1, threads, ip))
                errorfile.write('[{}] {} ERROR: No Connections available. \n'.format(datetime.now().strftime('%H:%M:%S'), ip))
            q.task_done()
            break

        # create two variables - one of hostname and the prompt level and another with just the hostname
        prompt = net_connect.find_prompt()
        hostname = prompt.rstrip('#>')
        print('Th{}/{}: Associated IP: {} with hostname: {}'.format(i+1, threads, ip, hostname))

        # timenow = '{:%Y-%m-%d %H_%M_%S}'.format(datetime.now())
        datenow = '{:%Y-%m-%d}'.format(datetime.now())
        start = datetime.now()
        # filename = 'IPtoDNS output.txt'
        # outputfile = open('IPtoDNS output/' + filename.format(timenow), 'w')

        print('Th{}/{}: Writing file name "{} {} - IPtoDNS raw output {}.txt"'.format(i+1, threads, hostname, ip, datenow))

        if device_os == 'cisco_ios':
            # for cmd in commands:
            try:
                if re.match(r'\w', cmd):
                    output = net_connect.send_command(cmd.strip(), delay_factor=1, max_loops=1000)
                    parsed_data = parse_show_ip_int_brief(output, hostname)
                    write_csv(csvfile, parsed_data)
                    write_rawfile(rawoutputfile, prompt, cmd, output)
                    # write_file(outputfile, prompt, cmd, output)
                else:
                    rawoutputfile.write(prompt + cmd + '\n')
            except (NetMikoTimeoutException, EOFError, OSError) as e:
                exception_logging(e, i, threads, ip, hostname, cmd, prompt, rawoutputfile, errorfile)
                net_connect = Netmiko(**device_dict)
                sleep(5)
        else:
            print("No match")

        # Disconnect from device
        net_connect.disconnect()

        # Close the file
        rawoutputfile.close()
        errorfile.close()
        csvfile.close()
        infoblox_csv.close()

        # verify elapsed time per device
        end = datetime.now()
        print('Th{}/{}: Completed. Time elapsed: {}'.format(i+1, threads, (end-start)))

        # Set the queue task as complete, thereby removing it from the queue indefinitely
        q.task_done()


def exception_logging(e, i, threads, ip, hostname, cmd, prompt, rawoutputfile, errorfile):
    print('Th{}/{}: Exception occurred: {}'.format(i + 1, threads, repr(e)))
    print('Th{}/{}: ERROR: Connection lost. Reconnecting to: {} ({})\n'.format(i + 1, threads, ip, hostname))
    rawoutputfile.write('{} {} !!!!!Command failed - run manually!!!!!\n'.format(prompt, cmd))
    errorfile.write('[{}] {} ({}) failed to run command: {}\n'.format(
        datetime.now().strftime('%H:%M:%S'), ip, hostname, cmd))


def parse_show_ip_int_brief(output, hostname):
    lines = output.strip().split('\n')
    headers = lines[0].split()
    data = []

    # TODO Create an exclude interface filter
    # exclude_int = ['Tu', 'Ucse']

    for line in lines[1:]:
        columns = re.split(r'\s+', line.strip())
        interface_full = columns[0]
        ip_address = columns[1]
        status = columns[4].lower()
        prot_status = columns[5].lower()

        if status == 'up' and prot_status == 'up' and ip_address != 'unassigned':
            interface_short = f"{hostname}-{re.match(r'([a-zA-Z]+)', interface_full).group(1)[:2]}{interface_full[len(re.match(r'([a-zA-Z]+)', interface_full).group(1)):]}"
            data.append({'interface': interface_short, 'ip_address': ip_address})

    return data


def write_csv(csvfile, parsed_data):
    # Writes to 'parsed_data + <date>.csv' file
    writer = csv.DictWriter(csvfile, fieldnames=['interface', 'ip_address'])
    # writer.writeheader()
    writer.writerows(parsed_data)
    #
    # with open(csvfile, 'a', newline='') as csvfile:
    #    writer = csv.DictWriter(csvfile, fieldnames=['interface', 'ip_address'])
    #    writer.writeheader()
    #    writer.writerows(parsed_data)


def write_rawfile(rawoutputfile, prompt, cmd, output):
    # Writes to 'IPtoDNS raw output + <date>.txt' file
    # Takes in variables (rawoutputfile, prompt, cmd, output) and writes output to file
    rawoutputfile.write((prompt + '\n') * 3)
    rawoutputfile.write(prompt + cmd + '\n')
    rawoutputfile.write(output + '\n')


# def write_infoblox_import(infoblox_csv, output):
    # Writes to 'infoblox_import <date>.csv' file


def main():
    # Setting up threads based on number set above
    for i in range(threads):
        # Create the thread using 'deviceconnector' as the function, passing in
        # the thread number and queue object as parameters
        thread = threading.Thread(target=deviceconnector, args=(i, enclosure_queue))
        # Set the thread as a background daemon/job
        # thread.setDaemon(True)
        thread.daemon = True
        # Start the thread
        thread.start()

    # For each ip address in "ip_addrs", add that IP address to the queue
    for ip_addr in ip_addrs:
        enclosure_queue.put(ip_addr)

    # Wait for all tasks in the queue to be marked as completed (task_done)
    enclosure_queue.join()
    # outputfile.close()
    print("*****\nCompleting IPtoDNS process ...\n*****")


if __name__ == '__main__':
    try:
        main()
    except ValueError:
        print('No Valhalla for you')
        sys.exit()
