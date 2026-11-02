#!/usr/bin/env python3
"""Read a log file, categorize IP addresses, and flag repeated addresses."""

import argparse
import csv
import json
import ipaddress
from pathlib import Path
import sys
import time


def write_report(path, counts):
	report = {
		"source_ips": [
			{
				"address": ip,
				"version": address.version,
				"count": count,
				"potential_intrusion": count > 1,
				"alert": "POTENTIAL INTRUSION" if count > 1 else None,
			}
			for ip, (address, count) in counts.items()
		]
	}
	with open(path, "w", encoding="utf-8") as output:
		json.dump(report, output, indent=2)
		output.write("\n")


def read_log(path, output_path, follow=False):
	counts = {}
	with open(path, encoding="utf-8-sig", errors="replace", newline="") as log:
		reader = csv.reader(log)
		source_index = None
		try:
			while True:
				try:
					row = next(reader)
				except StopIteration:
					if follow:
						time.sleep(0.2)
						continue
					break

				if source_index is None:
					headers = [header.strip().lower() for header in row]
					if "src_ip" not in headers:
						raise ValueError("CSV file must contain a 'src_ip' column")
					source_index = headers.index("src_ip")
					continue

				if source_index >= len(row):
					continue
				try:
					address = ipaddress.ip_address(row[source_index].strip())
				except ValueError:
					continue

				ip = str(address)
				previous_address, previous_count = counts.get(ip, (address, 0))
				counts[ip] = (previous_address, previous_count + 1)
				write_report(output_path, counts)
		finally:
			write_report(output_path, counts)


def main():
	parser = argparse.ArgumentParser(description="Analyze source IP addresses in a CSV log.")
	parser.add_argument("logfile", nargs="?", help="path to the log or .txt file")
	parser.add_argument("-o", "--output", help="JSON report path (default: alert.json beside the input)")
	parser.add_argument("-f", "--follow", action="store_true", help="watch appended log lines")
	args = parser.parse_args()
	logfile = args.logfile or input("Enter the path to the log or .txt file: ")
	output_path = Path(args.output) if args.output else Path(logfile).with_name("alert.json")
	if Path(logfile).resolve() == output_path.resolve():
		print("Cannot write the JSON report over the input file.", file=sys.stderr)
		return 1
	try:
		read_log(logfile, output_path, args.follow)
	except KeyboardInterrupt:
		return 0
	except ValueError as error:
		print(f"Cannot analyze {logfile}: {error}", file=sys.stderr)
		return 1
	except OSError as error:
		print(f"Cannot read or write the report for {logfile}: {error}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())

