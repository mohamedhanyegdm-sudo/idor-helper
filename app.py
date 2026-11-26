from flask import Flask, render_template_string, request
from idor_helper.analyzer import analyze_responses, build_report

app = Flask(__name__)

PAGE = '''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>IDOR Helper</title>
<style>
:root{color-scheme:dark}body{margin:0;background:#0b1020;color:#e8edf7;font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:38px auto;padding:0 18px}h1{margin-bottom:4px}
.sub{color:#aab6ce}.notice{background:#251d12;border:1px solid #80602d;padding:12px 14px;border-radius:10px;margin:18px 0}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}label{display:block;font-weight:650;margin:8px 0}
textarea{box-sizing:border-box;width:100%;min-height:270px;background:#111a30;color:#e8edf7;border:1px solid #33415f;border-radius:10px;padding:12px;font:13px/1.5 ui-monospace,monospace}
button{margin:16px 0;background:#5b8cff;color:white;border:0;border-radius:9px;padding:12px 20px;font-weight:700}
.panel{background:#111a30;border:1px solid #263653;border-radius:12px;padding:16px;margin:14px 0}
.tag{display:inline-block;padding:3px 8px;border-radius:20px;background:#283654;margin:3px}
pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style></head>
<body><main>
<h1>IDOR Helper</h1><div class="sub">Local HTTP response comparison · MVP 1.0</div>
<div class="notice"><b>Authorized testing only.</b> This tool does not send network requests. Paste responses captured from systems you are allowed to test. Remove secrets and personal data first.</div>
<form method="post">
<div class="grid">
<div><label for="a">Response A (e.g. User A)</label><textarea id="a" name="response_a" placeholder="HTTP/1.1 200 OK&#10;Content-Type: application/json&#10;&#10;{...}">{{ response_a or '' }}</textarea></div>
<div><label for="b">Response B (e.g. User B / comparison)</label><textarea id="b" name="response_b" placeholder="HTTP/1.1 403 Forbidden&#10;Content-Type: application/json&#10;&#10;{...}">{{ response_b or '' }}</textarea></div>
</div><button type="submit">Analyze responses</button>
</form>
{% if result %}
<div class="panel"><h2>Analysis</h2>
<p><b>Assessment:</b> {{ result.assessment }}</p>
<p><b>Status:</b> {{ result.status_a }} vs {{ result.status_b }}</p>
<p><b>Body similarity:</b> {{ result.similarity_percent }}%</p>
{% for item in result.observations %}<div>• {{ item }}</div>{% endfor %}
<h3>Header differences</h3>{% for item in result.header_differences %}<div><code>{{ item }}</code></div>{% else %}<div>No meaningful header differences detected.</div>{% endfor %}
<h3>Important</h3><p>{{ result.caveat }}</p>
</div>
<div class="panel"><h2>Report draft</h2><pre>{{ report }}</pre></div>
{% endif %}
</main></body></html>
'''

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    report = None
    response_a = response_b = ""
    if request.method == "POST":
        response_a = request.form.get("response_a", "")
        response_b = request.form.get("response_b", "")
        result = analyze_responses(response_a, response_b)
        report = build_report(result)
    return render_template_string(PAGE, result=result, report=report,
                                  response_a=response_a, response_b=response_b)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
