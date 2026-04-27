import click
from openetr.commands.core import info, init_config, profile_group, set_config, trivia, version
from openetr.commands.publish import publish_object, publish_profile
from openetr.commands.query import query_object, query_profile


@click.group()
def main() -> None:
    """OpenETR command line utility."""


main.add_command(version)
main.add_command(info)
main.add_command(init_config)
main.add_command(profile_group)
main.add_command(set_config)
main.add_command(trivia)
main.add_command(publish_object)
main.add_command(publish_profile)
main.add_command(query_object)
main.add_command(query_profile)
