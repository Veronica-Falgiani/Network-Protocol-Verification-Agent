from datetime import datetime
import os


def result(found_ports: dict, services: dict):
    file_name = "res/results_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S") + ".txt"
    os.makedirs(os.path.dirname(file_name), exist_ok=True)

    with open(file_name, "w") as res_file:
        res_file.write("##### RESULTS #####\n\n")
        res_file.write("PORT \t STATUS \t SERVICE\n")
        res_file.write("----------------------------\n")
        for port, status in found_ports.items():
            res_file.write(f"{str(port)} \t {status} \t {services[port]}\n")

    print(f"\nResults can be found in: {file_name}")
