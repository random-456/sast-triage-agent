import click
import logging
import sys

class CommaList(click.ParamType):
    """
    A Click parameter type that accepts either a comma-separated list of strings
    """
    name = 'comma_list'

    logger = logging.getLogger(__name__)

    def convert(self, value, param, ctx):
        if value is None:
            return []

        try:
            return [item.strip() for item in value.split(',')]
        except AttributeError:
            self.logger.error(f"'{value}' is not a valid comma-separated string")
            sys.exit(-1)