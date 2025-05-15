import os
from datetime import datetime
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
from agent.results import Results


TIME = "Result_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S")
RES_DIR = "res/" + TIME + "/"


def write_result(report: Results):
    # Creates directories for result files (if they don't exist)
    os.makedirs(os.path.dirname("res/"), exist_ok=True)
    os.makedirs(os.path.dirname(RES_DIR), exist_ok=True)
    os.makedirs(os.path.dirname(f"{RES_DIR}img/"), exist_ok=True)
    os.chmod("res/", 0o777)
    os.chmod(f"{RES_DIR}", 0o777)
    os.chmod(f"{RES_DIR}img/", 0o777)

    txt_result(report)
    # html_result(report)


def txt_result(report):
    file_txt = RES_DIR + f"{report.ip}_results.txt"

    with open(file_txt, "w") as res_file:
        res_file.write(f"##### RESULTS  FOR {report.ip}#####\n\n")
        res_file.write("PORT \t PROTOCOL \t SERVICE\n")
        res_file.write("----------------------------\n")

        for result in report.report:
            res_file.write(str(result))

    print(f"Results can be found in: {file_txt}")


def html_result(report: Results):
    # Creates a directory (if it doesn't exist) and a result file
    file_html = RES_DIR + f"{report.ip}_results.html"

    html_title = ""
    html_version = ""
    html_tests = ""
    html_tls = ""
    html_pills = ""

    for result in report.report:
        html_title = f"""
            <div id={result.prot} class="tab-pane fade">
            <h3><b>Port {result.port} - {result.prot} - {result.service}</b></h3>
            <hr>
        """

        html_version = f"""
            <div class='my-3'>
                <p>Service vulnerable: {result.unsafe_ver}</p>
            </div>
        """

        if "SSL" in result.service or "TLS" in result.service:
            html_tls = f"""
                <div class='my-3'>
                    <p>SSL/TLS protocol vulnerable: {result.unsafe_tls}</p>
                </div>
            """

        # Checks if there are vulns to print
        if result.max_vulns == 0:
            html_tests += """
                <p class="my-3">No tests found for the protocol</p>
                </div>
            """

            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}"><del>{result.prot}</del></button></li>
            """

        # Checks if the protocol has tests or not
        elif len(result.vulns) != 0:
            severity_html = {
                "high": 0,
                "high_results": "",
                "medium": 0,
                "medium_results": "",
                "low": 0,
                "low_results": "",
                "ok": 0,
            }

            html_tests += f"""
                <div id={result.prot} class="tab-pane fade">
                <h3><b>Port {result.port} - {result.prot} - {result.service}</b></h3>
                <hr>
                <img src="img/{result.prot}.png" width="400">
                <ul>
            """

            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}" style="color:red"><b>{result.prot}</b></button></li>
            """

            for vuln in result.vulns:
                match vuln["severity"]:
                    case "high":
                        severity_html["high"] += 1
                        severity_html["high_results"] += f"""
                            <li class='my-3'><b> {vuln["name"]} </b><br> description: {vuln["description"]}</li> 
                        """

                    case "medium":
                        severity_html["medium"] += 1
                        severity_html["medium_results"] += f"""
                            <li class='my-3'><b> {vuln["name"]} </b><br> description: {vuln["description"]}</li> 
                        """

                    case "low":
                        severity_html["low"] += 1
                        severity_html["low_results"] += f"""
                            <li class='my-3'><b> {vuln["name"]} </b><br> description: {vuln["description"]}</li> 
                        """

            html_tests += (
                f"<li style='color:#EC6B56'><h5><b> HIGH: {severity_html['high']} </b></h5></li>"
                + f"<ul class='mb-4'> {severity_html['high_results']}</ul>"
                + f"<li style='color:#FFC154'><h5><b> MEDIUM: {severity_html['medium']} </b></h5></li>"
                + f"<ul class='mb-4'>{severity_html['medium_results']}</ul>"
                + f"<li style='color:#47B39C'><h5><b> LOW: {severity_html['low']} </b></h5></li>"
                + f"<ul class='mb-4'> {severity_html['low_results']}</ul>"
                + "</ul></div>"
            )

            draw_graph(severity_html, result)

        # No tests for the specified protocol
        else:
            html_tests += """
                <p class="my-3">The service has been tested and no vulns have been found</p>
                </div>
            """

            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}" style="color:green"><b>{result.prot}</b></button></li>
            """

    # Setup html template via jinja2 and write to file
    env = Environment(loader=FileSystemLoader("utils"))
    template = env.get_template("report_template.html")

    html = template.render(
        page_title_text=f"Result {TIME}",
        title_text=f"Report for {report.ip}",
        html_pills=html_pills,
        html_title=html_title,
        html_version=html_version,
        html_tls=html_tls,
        html_tests=html_tests,
    )

    with open(file_html, "w") as res_file:
        res_file.write(html)


def draw_graph(severity_html: dict, result: Results):
    labels = "high", "medium", "low", "ok"
    colors = ["#EC6B56", "#FFC154", "#47B39C", "skyblue"]

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

    plt.savefig(f"{RES_DIR}/img/{result.prot}.png", transparent=True)
    plt.clf()
