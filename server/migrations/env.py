from alembic import context

from server.database import engine

with engine().connect() as conn:
    context.configure(connection=conn)
    with context.begin_transaction():
        context.run_migrations()
