from datetime import datetime
import os


def txt_result(found_ports: dict, report: list):
    # Creates a directory (if it doesn't exist) and a result file
    file_name = "res/results_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S") + ".txt"
    os.makedirs(os.path.dirname(file_name), exist_ok=True)
    os.chmod("res/", 0o777)

    with open(file_name, "w") as res_file:
        res_file.write("##### RESULTS #####\n\n")
        res_file.write("PORT \t PROTOCOL \t SERVICE\n")
        res_file.write("----------------------------\n")

        for result in report:
            res_file.write(f"\n{result.port} \t {result.prot} \t {result.service}\n")

            # No test found for the protocol
            if len(result.vulns) == 0:
                res_file.write("|\\_ --- NO TESTS FOUND FOR THIS PROTOCOL ---\n")

            # writes a line for every test that has found a vulnerability in the protocol
            else:
                for vuln in result.vulns:
                    res_file.write(f"|\\_ {vuln['name']}\n")
                    res_file.write(f"|   description: {vuln['description']}\n")
                    res_file.write(f"|   severity: {vuln['severity']}\n")

    print(f"\nResults can be found in: {file_name}")
