from jinja2 import Environment, FileSystemLoader, select_autoescape
import pdfkit
import os

def render_pdf(findings, summary, outfile="report.pdf"):
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")), autoescape=select_autoescape())
    template = env.get_template("report.html.j2")
    html = template.render(summary=summary, findings=findings)
    pdfkit.from_string(html, outfile)
    return outfile

