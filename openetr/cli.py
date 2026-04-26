import click
from openetr.commands.core import hello, init_config, set_config, version
from openetr.commands.publish import publish_object
from openetr.commands.query import query_object, query_profile


@click.group()
def main() -> None:
    """OpenETR command line utility."""


main.add_command(version)
main.add_command(init_config)
main.add_command(set_config)
main.add_command(hello)
main.add_command(publish_object)
main.add_command(query_object)
main.add_command(query_profile)
