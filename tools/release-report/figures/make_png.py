"""Renders fig1.svg / fig2.svg to PNG (3x) with Playwright + Chromium. Only needed when the figures are changed:
   python3 make_svg.py && python3 make_png.py   (pip install playwright; playwright install chromium; or set CHROMIUM to a chromium binary)"""
import os, pathlib
from playwright.sync_api import sync_playwright
HERE=os.path.dirname(os.path.abspath(__file__))
with sync_playwright() as p:
    kw={'executable_path':os.environ['CHROMIUM']} if os.environ.get('CHROMIUM') else {}
    b=p.chromium.launch(**kw)
    for n,(w,h) in {'fig1':(780,560),'fig2':(780,330)}.items():
        pg=b.new_page(viewport={'width':w,'height':h},device_scale_factor=3)
        pg.goto(pathlib.Path(HERE,n+'.svg').as_uri()); pg.screenshot(path=os.path.join(HERE,n+'.png')); pg.close()
    b.close()
