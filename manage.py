#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'encrypTest.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()

'''
#!/usr/bin/env python
import os
import sys
import certifi
import requests
import urllib3

try:
    import pymysql
    pymysql.install_as_MySQLdb()
except ImportError:
    pass

if __name__ == "__main__":
    try:
        if os.environ.get('SIMTEX_ENV') == 'development':
            requests.get('https://smile-aus-dev.star.zetta.com.au')
        elif os.environ.get('SIMTEX_ENV') == 'production':
            requests.get('https://smile-aus-live.star.zetta.com.au')

    except (requests.exceptions.SSLError, urllib3.exceptions.MaxRetryError) as err:
        print('SSL Error. Adding ZG-CA-20161014.crt to cert store...')
        cafile = certifi.where()
        with open('ZG-CA-20161014.crt', 'rb') as infile:
            customca = infile.read()
        with open(cafile, 'ab') as outfile:
            outfile.write(customca)
        print('Added')

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "simtexapi.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)

'''