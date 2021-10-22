import argparse
from webscreenshot.webscreenshot import take_screenshot
from typing import List


def website_screenshot(urls: List[str], output_dir: str):
    """
    Perform screenshot of designated websites
    Parameters
    ----------
    urls : List[str]
        List of IP or domain name on which perform a screenshot
    output_dir : str
            Path to the directory where the screenshots will be stored
oc
    Returns
    -------

    """

    if len(urls) != 0:
        options = argparse.Namespace(
            URL=None, ajax_max_timeouts='1400,1800', cookie=None, crop=None, format='png', header=None,
            http_password=None, http_username=None, imagemagick_binary=None, input_file=None, label=False,
            label_bg_color='NavajoWhite', label_size=120, log_level='ERROR', multiprotocol=True, no_xserver=False,
            output_directory=output_dir, port=None, proxy="", proxy_auth=None, proxy_type=None, quality=100,
            renderer='chromium', renderer_binary="sudo /usr/bin/chromium-browser", ssl=False, timeout=30, verbosity=0,
            window_size='1920,1080', workers=4
        )
        take_screenshot(urls, options)
