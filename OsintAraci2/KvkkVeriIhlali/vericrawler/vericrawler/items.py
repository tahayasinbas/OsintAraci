# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class VericrawlerItem2(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    pass
class VericrawlerItem(scrapy.Item):
    AramaSonucuBaslik = scrapy.Field()
    AramaSonucYazi = scrapy.Field()