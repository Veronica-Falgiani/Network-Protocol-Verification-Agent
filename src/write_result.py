from datetime import datetime
import os


def result(found_ports: dict, services: dict, report: dict):
    file_name = "res/results_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S") + ".txt"
    os.makedirs(os.path.dirname(file_name), exist_ok=True)

    with open(file_name, "w") as res_file:
        res_file.write("##### RESULTS #####\n\n")
        res_file.write("PORT \t STATUS \t SERVICE\n")
        res_file.write("----------------------------\n")

        for port, status in found_ports.items():
            res_file.write(f"\n{str(port)} \t {status} \t {services[port]}\n")
            results = report[port]

            for name, info in results.items():
                res_file.write(f"|\n")
                res_file.write(f"|\\_ {name}\n")
                res_file.write(f"|   description: {info['description']}\n")
                res_file.write(f"|   severity: {info['severity']}\n")

    print(f"\nResults can be found in: {file_name}")
