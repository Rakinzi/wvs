from app import create_app
from app.commands import register_commands

app = create_app()
register_commands(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)