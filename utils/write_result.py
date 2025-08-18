import os
from datetime import datetime
import matplotlib.pyplot as plt
import json
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

    log_result(report)
    json_result(report)
    html_result(report)

    print(f"Results can be found in: {RES_DIR}")


# Writes a human readable log
def log_result(report):
    file_log = RES_DIR + f"{report.ip}_results.log"

    with open(file_log, "w") as res_file:
        res_file.write(f"##### RESULTS FOR {report.ip} #####\n\n")
        res_file.write("PORT \t PROTOCOL \t SERVICE\n")
        res_file.write("----------------------------\n\n\n")

        for result in report.report:
            res_file.write(str(result))


# Creates a json file with all the results
def json_result(report):
    file_json = RES_DIR + f"{report.ip}_results.json"

    with open(file_json, "w") as res_file:
        res_dict = {
            "ip": report.ip,
            "timestamp": datetime.today().strftime("%Y-%m-%d_%H:%M:%S"),
            "services": [],
        }

        for result in report.report:
            res_dict["services"].append(result.__json__())

        json.dump(res_dict, res_file, indent=4)


# Creates a html page with results and graphs
def html_result(report: Results):
    # Creates a directory (if it doesn't exist) and a result file
    file_html = RES_DIR + f"{report.ip}_results.html"

    html_pills = ""
    html_title = ""
    html_protocols = ""

    for result in report.report:
        html_version = ""
        html_tls = ""
        html_misconfigs = ""
        html_auth_misconfigs = ""

        # Protocol name and service version
        html_title = f"""
            <div id={result.prot}-{result.port} class="tab-pane fade">
                <h3><b>Port {result.port} - {result.prot} - {result.service}</b></h3>
        """

        # Result after checking service version
        if not result.unsafe_ver:
            html_version = """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> SERVICE VERSION </h4>
                    <p>This service version is not vulnerable</p>
                </div>
            """
        else:
            html_version = """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> SERVICE VERSION </h4>
                    <p><b>This service version is vulnerable, an update is mandatory!</b></p>
                    <p>Reference CVE:<p>
                    <ul>
                """

            for cve in result.unsafe_ver_cve:
                cve_number = cve.split("?id=")[1]
                html_version += f"""
                    <li><a href="{cve}" target="_blank">{cve_number}</a></li>
                """

            html_version += """
                </ul>
                </div>
            """

        # Result for checking TLS version
        if "SSL" in result.service or "TLS" in result.service:
            if result.unsafe_tls:
                html_tls = """
                    <div class='my-3'>
                        <hr>
                        <h4 style="text-align:center"> SSL/TLS PROTOCOL VERSION </h4>
                        <p><b>The SSL/TLS version used is deprecated!</b></p>
                    </div>
                """
            else:
                html_tls = """
                    <div class='my-3'>
                        <hr>
                        <h4 style="text-align:center"> SSL/TLS PROTOCOL VERSION </h4>
                        <p>The SSL/TLS version used is still supported</p>
                    </div>
                """

                

        # Checks if there are misconfigs to print
        if (result.serv_max_misconfigs + result.prot_max_misconfigs) == 0:
            html_misconfigs += """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> MISCONFIGURATIONS </h4>
                    <p class="my-3">No tests found for the protocol</p>
                </div>
            """

        # Checks if the protocol has misconfigs or not
        elif len(result.vuln_misconfigs) != 0:
            severity_html = {
                "high": 0,
                "high_results": "",
                "medium": 0,
                "medium_results": "",
                "low": 0,
                "low_results": "",
                "ok": 0,
            }

            html_misconfigs += f"""
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> MISCONFIGURATIONS </h4>
                    <img src="img/{result.prot}-{result.port}.png" width="400">
                    <ul>
            """

            for vuln in result.vuln_misconfigs:
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

            html_misconfigs += (
                f"<li style='color:#EC6B56'><h5><b> HIGH: {severity_html['high']} </b></h5></li>"
                + f"<ul class='mb-4'> {severity_html['high_results']}</ul>"
                + f"<li style='color:#FFC154'><h5><b> MEDIUM: {severity_html['medium']} </b></h5></li>"
                + f"<ul class='mb-4'>{severity_html['medium_results']}</ul>"
                + f"<li style='color:#47B39C'><h5><b> LOW: {severity_html['low']} </b></h5></li>"
                + f"<ul class='mb-4'> {severity_html['low_results']}</ul>"
                + "</ul></div>"
            )

            draw_graph(
                severity_html,
                result,
                (result.prot_max_misconfigs + result.serv_max_misconfigs),
                "",
            )

        # No misconfigs for the specified protocol
        else:
            html_misconfigs += """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> MISCONFIGURATIONS </h4>
                    <p class="my-3">The service has been tested and no misconfigurations have been found</p>
                </div>
            """

        # Checks if there are misconfigs to print
        if (result.prot_max_auth_misconfigs + result.serv_max_auth_misconfigs) == 0:
            html_auth_misconfigs += """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> AUTHENTICATED MISCONFIGURATIONS </h4>
                    <p class="my-3">No tests found for the protocol</p>
                </div>
            """

        elif not result.prot_auth and not result.serv_auth:
            html_auth_misconfigs += """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> AUTHENTICATED MISCONFIGURATIONS </h4>
                    <p class="my-3">No credentials were given</p>
                </div>
            """

        # Checks if the protocol has misconfigs or not
        elif len(result.vuln_auth_misconfigs) != 0:
            severity_html = {
                "high": 0,
                "high_results": "",
                "medium": 0,
                "medium_results": "",
                "low": 0,
                "low_results": "",
                "ok": 0,
            }

            html_auth_misconfigs += f"""
                <div id={result.prot}>
                    <hr>
                    <h4 style="text-align:center"> AUTHENTICATED MISCONFIGURATIONS </h4>
                    <img src="img/{result.prot}-{result.port}auth.png" width="400">
                    <ul>
            """

            for vuln in result.vuln_auth_misconfigs:
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

            html_auth_misconfigs += (
                f"<li style='color:#EC6B56'><h5><b> HIGH: {severity_html['high']} </b></h5></li>"
                + f"<ul class='mb-4'> {severity_html['high_results']}</ul>"
                + f"<li style='color:#FFC154'><h5><b> MEDIUM: {severity_html['medium']} </b></h5></li>"
                + f"<ul class='mb-4'>{severity_html['medium_results']}</ul>"
                + f"<li style='color:#47B39C'><h5><b> LOW: {severity_html['low']} </b></h5></li>"
                + f"<ul class='mb-4'> {severity_html['low_results']}</ul>"
                + "</ul></div>"
            )

            draw_graph(
                severity_html,
                result,
                (result.prot_max_auth_misconfigs + result.serv_max_auth_misconfigs),
                "auth",
            )

        # No misconfigs for the specified protocol
        else:
            html_auth_misconfigs += """
                <div class='my-3'>
                    <hr>
                    <h4 style="text-align:center"> AUTHENTICATED MISCONFIGURATIONS </h4>
                    <p class="my-3">The service has been tested and no misconfigurations have been found</p>
                </div>
            """

        # Adding buttons for protocols
        if (
            (result.prot_max_misconfigs + result.serv_max_misconfigs) == 0
            and (result.prot_max_auth_misconfigs + result.serv_max_auth_misconfigs) == 0
            and not result.unsafe_ver
        ):
            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}-{result.port}"><del>{result.prot}-{result.port}</del></button></li>
            """
        elif (
            len(result.vuln_misconfigs) != 0
            or len(result.vuln_auth_misconfigs) != 0
            or result.unsafe_ver
        ):
            html_pills += f""" 
                <button class=" nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}-{result.port}" style="color:red"><b>{result.prot}-{result.port}</b></button></li>
            """
        else:
            html_pills += f""" 
                <button class="nav-link" type="button" data-bs-toggle="pill" data-bs-target="#{result.prot}-{result.port}" style="color:green"><b>{result.prot}-{result.port}</b></button></li>
            """

        html_protocols += (
            html_title
            + html_version
            + html_tls
            + html_misconfigs
            + html_auth_misconfigs
            + "</div>"
        )

    # Setup html template via jinja2 and write to file
    env = Environment(loader=FileSystemLoader("utils"))
    template = env.get_template("report_template.html")

    html = template.render(
        page_title_text=f"Result {TIME}",
        title_text=f"Report for {report.ip}",
        html_pills=html_pills,
        html_protocols=html_protocols,
    )

    with open(file_html, "w") as res_file:
        res_file.write(html)


# Creates a png image of a pie chart based on the results of a protocol
def draw_graph(severity_html: dict, result: Results, max_vulns: int, type: str):
    labels = "high", "medium", "low", "ok"
    colors = ["#EC6B56", "#FFC154", "#47B39C", "skyblue"]

    severity_html["ok"] = (
        max_vulns
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

    plt.savefig(
        f"{RES_DIR}/img/{result.prot}-{result.port}{type}.png", transparent=True
    )
    plt.clf()
