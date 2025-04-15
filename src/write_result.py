from datetime import datetime
import os


def result(found_ports: dict, services: dict, report: dict):
    # Creates a directory (if it doesn't exist) and a result file
    file_name = "res/results_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S") + ".txt"
    os.makedirs(os.path.dirname(file_name), exist_ok=True)
    os.chmod("res/", 0o777)

    with open(file_name, "w") as res_file:
        res_file.write("##### RESULTS #####\n\n")
        res_file.write("PORT \t STATUS \t SERVICE\n")
        res_file.write("----------------------------\n")

        for port, status in found_ports.items():
            if services[port] != "undefined":
                res_file.write(f"\n{str(port)} \t {status} \t {services[port]}\n")

                # writes a line for every test that has found a vulnerability in the protocol
                if port in report.keys():
                    results = report[port]

                    for name, info in results.items():
                        res_file.write("|\n")
                        res_file.write(f"|\\_ {name}\n")
                        res_file.write(f"|   description: {info['description']}\n")
                        res_file.write(f"|   severity: {info['severity']}\n")

                # No test found for the protocol
                else:
                    res_file.write("|\n")
                    res_file.write("|\\_ --- NO TESTS FOUND FOR THIS PROTOCOL ---\n")

    print(f"\nResults can be found in: {file_name}")
