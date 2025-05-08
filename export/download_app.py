from flask import Flask, send_from_directory, render_template

app = Flask(__name__, template_folder='downloads')

@app.route('/')
def download_page():
    return render_template('index.html')

@app.route('/project.zip')
def download_project():
    return send_from_directory('downloads', 'project.zip')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)