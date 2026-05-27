import os
import logging

from flask import Flask, jsonify, send_from_directory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def ok(data, **extra):
    res = {"ok": True, "data": data}
    res.update(extra)
    return jsonify(res)


def err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def create_app():
    static_dir = os.path.join(os.path.dirname(__file__), "..", "static", "dist")
    if not os.path.isdir(static_dir):
        static_dir = os.path.join(os.path.dirname(__file__), "..", "static")

    app = Flask(__name__, static_url_path="", static_folder=static_dir)

    from .routes.upload import upload_bp
    from .routes.analysis import analysis_bp
    from .routes.chat import chat_bp
    from .routes.config_routes import config_bp
    from .routes.databases import databases_bp
    from .remote.routes import remote_bp

    app.register_blueprint(upload_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(databases_bp)
    app.register_blueprint(remote_bp)

    @app.route("/")
    def root():
        return send_from_directory(app.static_folder, "index.html")

    return app
