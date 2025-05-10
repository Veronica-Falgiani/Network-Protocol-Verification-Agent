from datetime import datetime
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
import os


def write_result(report: list, ip: str):
    time = "Result_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S")
    res_dir = "res/" + time + "/"

    # Creates directories for result files (if they don't exist)
    os.makedirs(os.path.dirname("res/"), exist_ok=True)
    os.makedirs(os.path.dirname(res_dir), exist_ok=True)
    os.makedirs(os.path.dirname(f"{res_dir}img/"), exist_ok=True)
    os.chmod("res/", 0o777)
    os.chmod(f"{res_dir}", 0o777)
    os.chmod(f"{res_dir}img/", 0o777)

    txt_result(report, res_dir, time, ip)
    html_result(report, res_dir, time, ip)


def txt_result(report: list, res_dir: str, time: str, ip: str):
    file_txt = res_dir + f"{ip}_results.txt"

    with open(file_txt, "w") as res_file:
        res_file.write(f"##### RESULTS  FOR {ip}#####\n\n")
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

    print(f"\nResults can be found in: {file_txt}")


def html_result(report: list, res_dir: str, time: str, ip: str):
    # Creates a directory (if it doesn't exist) and a result file
    file_html = res_dir + f"{ip}_results.html"

    labels = "high", "medium", "low", "ok"
    colors = ["#EC6B56", "#FFC154", "#47B39C", "skyblue"]

    html_results = ""
    html_pills = ""

    for result in report:
        # Checks if the protocol has been tested or not
        if result.max_vulns != 0:
            severity_html = {
                "high": 0,
                "high_results": "",
                "medium": 0,
                "medium_results": "",
                "low": 0,
                "low_results": "",
                "ok": 0,
            }

            html_results += f"""
                <div id={result.prot} class="tab-pane fade">
                <h3><b>Port {result.port} - {result.prot} - {result.service}</b></h3>
                <hr>
                <img src="img/{result.prot}.png" width="400">
                <ul>
            """

            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}">{result.prot}</a></li>
            """

            for vuln in result.vulns:
                match vuln["severity"]:
                    case "high":
                        severity_html["high"] += 1
                        severity_html["high_results"] += f"""
                            <li> {vuln["name"]} </li> 
                        """

                    case "medium":
                        severity_html["medium"] += 1
                        severity_html["medium_results"] += f"""
                            <li> {vuln["name"]} </li> 
                        """

                    case "low":
                        severity_html["low"] += 1
                        severity_html["low_results"] += f"""
                            <li> {vuln["name"]} </li> 
                        """

            html_results += (
                f"<li style='color:#EC6B56'><b> HIGH: {severity_html['high']} </b></li><ul class='mb-4'>"
                + severity_html["high_results"]
                + f"</ul><li style='color:#FFC154'><b> MEDIUM: {severity_html['medium']}</b></li><ul class='mb-4'>"
                + severity_html["medium_results"]
                + f"</ul><li style='color:#47B39C'><b> LOW: {severity_html['low']} </b></li><ul class='mb-4'>"
                + severity_html["low_results"]
                + "</ul></ul></div>"
            )

            severity_html["ok"] = (
                result.max_vulns
                - severity_html["high"]
                - severity_html["medium"]
                - severity_html["low"]
            )

            # Creating pie chart for html
            sizes = [
                severity_html["high"],
                severity_html["medium"],
                severity_html["low"],
                severity_html["ok"],
            ]

            wedges, texts = plt.pie(
                sizes,
                labels=labels,
                startangle=90,
                colors=colors,
                textprops={"color": "w", "size": "x-large"},
            )

            # Updates labels with counters and removes labels that correspond to 0 vulns
            for label in texts:
                label_txt = label.get_text()
                label.set_text(f"{label_txt} - {severity_html[label_txt]}")
                if label_txt != "ok" and severity_html[label_txt] == 0:
                    label.set_text("")
                elif label_txt == "ok" and severity_html["ok"] == 0:
                    label.set_text("")

            plt.savefig(f"{res_dir}/img/{result.prot}.png", transparent=True)
            plt.clf()

        # No tests for the specified protocol
        else:
            html_results += f"""
                <div id={result.prot} class="tab-pane fade">
                <h3><u>Port {result.port} - {result.prot} - {result.service}</u></h3>
                <p>No tests found for the protocol</p>
                </div>
            """

            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}"><del>{result.prot}</del></a></li>
            """

    # Setup html template via jinja2 and write to file
    env = Environment(loader=FileSystemLoader("utils"))
    template = env.get_template("report_template.html")

    html = template.render(
        page_title_text=f"Result {time}",
        title_text=f"Report for {ip}",
        html_pills=html_pills,
        html_results=html_results,
    )

    with open(file_html, "w") as res_file:
        res_file.write(html)
