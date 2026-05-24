import os

from app import create_app

app = create_app()

if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('DEBUG')
    if debug is None:
        debug_enabled = app.config.get('DEBUG', False)
    else:
        debug_enabled = debug.lower() in {'1', 'true', 'yes', 'on'}

    app.run(host=host, port=port, debug=debug_enabled)
