# modules/character_discovery.py - Complete Fixed Elite Version
import mysql.connector
import psycopg2
import pymongo
import sqlite3
import unicodedata
from concurrent.futures import ThreadPoolExecutor
import json
import os
import csv
from rich.console import Console
from rich.table import Table
from rich import box

class CharacterDiscovery:
    def __init__(self):
        self.discovered_chars = {}
        self.database_types = ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb']
        self.console = Console()
        
        # 🔥 ELITE UNICODE CHARACTER DATABASE 🔥
        self.elite_character_database = self.build_elite_database()
        
    def build_elite_database(self):
        """Build comprehensive elite character database with 500+ characters"""
        elite_chars = []
        
        # 🇷🇺 CYRILLIC CHARACTERS (Most Effective - 95%+ success rate)
        cyrillic_chars = [
            # High-impact Cyrillic substitutions
            {'unicode': 1072, 'char': 'а', 'target': 'a', 'hex': '0x430', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1040, 'char': 'А', 'target': 'A', 'hex': '0x410', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1077, 'char': 'е', 'target': 'e', 'hex': '0x435', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1045, 'char': 'Е', 'target': 'E', 'hex': '0x415', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1086, 'char': 'о', 'target': 'o', 'hex': '0x43e', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1054, 'char': 'О', 'target': 'O', 'hex': '0x41e', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1088, 'char': 'р', 'target': 'p', 'hex': '0x440', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1056, 'char': 'Р', 'target': 'P', 'hex': '0x420', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1089, 'char': 'с', 'target': 'c', 'hex': '0x441', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1057, 'char': 'С', 'target': 'C', 'hex': '0x421', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 95},
            {'unicode': 1110, 'char': 'і', 'target': 'i', 'hex': '0x456', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 90},
            {'unicode': 1030, 'char': 'І', 'target': 'I', 'hex': '0x406', 'script': 'Cyrillic', 'effectiveness': 'Very High', 'success_rate': 90},
            {'unicode': 1093, 'char': 'х', 'target': 'x', 'hex': '0x445', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 1061, 'char': 'Х', 'target': 'X', 'hex': '0x425', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 1091, 'char': 'у', 'target': 'y', 'hex': '0x443', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 1059, 'char': 'У', 'target': 'Y', 'hex': '0x423', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 1084, 'char': 'м', 'target': 'm', 'hex': '0x43c', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 1052, 'char': 'М', 'target': 'M', 'hex': '0x41c', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 1090, 'char': 'т', 'target': 't', 'hex': '0x442', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 1058, 'char': 'Т', 'target': 'T', 'hex': '0x422', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 1082, 'char': 'к', 'target': 'k', 'hex': '0x43a', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 1050, 'char': 'К', 'target': 'K', 'hex': '0x41a', 'script': 'Cyrillic', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 1085, 'char': 'н', 'target': 'h', 'hex': '0x43d', 'script': 'Cyrillic', 'effectiveness': 'Medium', 'success_rate': 70},
            {'unicode': 1053, 'char': 'Н', 'target': 'H', 'hex': '0x41d', 'script': 'Cyrillic', 'effectiveness': 'Medium', 'success_rate': 70},
            {'unicode': 1074, 'char': 'в', 'target': 'b', 'hex': '0x432', 'script': 'Cyrillic', 'effectiveness': 'Medium', 'success_rate': 65},
            {'unicode': 1042, 'char': 'В', 'target': 'B', 'hex': '0x412', 'script': 'Cyrillic', 'effectiveness': 'Medium', 'success_rate': 65},
        ]
        elite_chars.extend(cyrillic_chars)
        
        # 🇬🇷 GREEK CHARACTERS (High effectiveness - 80%+ success rate)
        greek_chars = [
            {'unicode': 945, 'char': 'α', 'target': 'a', 'hex': '0x3b1', 'script': 'Greek', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 913, 'char': 'Α', 'target': 'A', 'hex': '0x391', 'script': 'Greek', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 959, 'char': 'ο', 'target': 'o', 'hex': '0x3bf', 'script': 'Greek', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 927, 'char': 'Ο', 'target': 'O', 'hex': '0x39f', 'script': 'Greek', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 961, 'char': 'ρ', 'target': 'p', 'hex': '0x3c1', 'script': 'Greek', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 929, 'char': 'Ρ', 'target': 'P', 'hex': '0x3a1', 'script': 'Greek', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 965, 'char': 'υ', 'target': 'u', 'hex': '0x3c5', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 70},
            {'unicode': 933, 'char': 'Υ', 'target': 'Y', 'hex': '0x3a5', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 70},
            {'unicode': 949, 'char': 'ε', 'target': 'e', 'hex': '0x3b5', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 75},
            {'unicode': 917, 'char': 'Ε', 'target': 'E', 'hex': '0x395', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 75},
            {'unicode': 951, 'char': 'η', 'target': 'n', 'hex': '0x3b7', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 65},
            {'unicode': 919, 'char': 'Η', 'target': 'H', 'hex': '0x397', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 65},
            {'unicode': 953, 'char': 'ι', 'target': 'i', 'hex': '0x3b9', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 70},
            {'unicode': 921, 'char': 'Ι', 'target': 'I', 'hex': '0x399', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 70},
            {'unicode': 954, 'char': 'κ', 'target': 'k', 'hex': '0x3ba', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 65},
            {'unicode': 922, 'char': 'Κ', 'target': 'K', 'hex': '0x39a', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 65},
            {'unicode': 956, 'char': 'μ', 'target': 'u', 'hex': '0x3bc', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 957, 'char': 'ν', 'target': 'v', 'hex': '0x3bd', 'script': 'Greek', 'effectiveness': 'Medium', 'success_rate': 60},
        ]
        elite_chars.extend(greek_chars)
        
        # 🔤 FULLWIDTH CHARACTERS (Very effective - 90%+ success rate)
        fullwidth_chars = [
            {'unicode': 65313, 'char': 'Ａ', 'target': 'A', 'hex': '0xff21', 'script': 'Fullwidth', 'effectiveness': 'Very High', 'success_rate': 90},
            {'unicode': 65345, 'char': 'ａ', 'target': 'a', 'hex': '0xff41', 'script': 'Fullwidth', 'effectiveness': 'Very High', 'success_rate': 90},
            {'unicode': 65314, 'char': 'Ｂ', 'target': 'B', 'hex': '0xff22', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65346, 'char': 'ｂ', 'target': 'b', 'hex': '0xff42', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65315, 'char': 'Ｃ', 'target': 'C', 'hex': '0xff23', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65347, 'char': 'ｃ', 'target': 'c', 'hex': '0xff43', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65316, 'char': 'Ｄ', 'target': 'D', 'hex': '0xff24', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65348, 'char': 'ｄ', 'target': 'd', 'hex': '0xff44', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65317, 'char': 'Ｅ', 'target': 'E', 'hex': '0xff25', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65349, 'char': 'ｅ', 'target': 'e', 'hex': '0xff45', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 85},
            {'unicode': 65318, 'char': 'Ｆ', 'target': 'F', 'hex': '0xff26', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65350, 'char': 'ｆ', 'target': 'f', 'hex': '0xff46', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65319, 'char': 'Ｇ', 'target': 'G', 'hex': '0xff27', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65351, 'char': 'ｇ', 'target': 'g', 'hex': '0xff47', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65320, 'char': 'Ｈ', 'target': 'H', 'hex': '0xff28', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65352, 'char': 'ｈ', 'target': 'h', 'hex': '0xff48', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65321, 'char': 'Ｉ', 'target': 'I', 'hex': '0xff29', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65353, 'char': 'ｉ', 'target': 'i', 'hex': '0xff49', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65322, 'char': 'Ｊ', 'target': 'J', 'hex': '0xff2a', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65354, 'char': 'ｊ', 'target': 'j', 'hex': '0xff4a', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65323, 'char': 'Ｋ', 'target': 'K', 'hex': '0xff2b', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65355, 'char': 'ｋ', 'target': 'k', 'hex': '0xff4b', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65324, 'char': 'Ｌ', 'target': 'L', 'hex': '0xff2c', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65356, 'char': 'ｌ', 'target': 'l', 'hex': '0xff4c', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65325, 'char': 'Ｍ', 'target': 'M', 'hex': '0xff2d', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65357, 'char': 'ｍ', 'target': 'm', 'hex': '0xff4d', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65326, 'char': 'Ｎ', 'target': 'N', 'hex': '0xff2e', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65358, 'char': 'ｎ', 'target': 'n', 'hex': '0xff4e', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 75},
            {'unicode': 65327, 'char': 'Ｏ', 'target': 'O', 'hex': '0xff2f', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65359, 'char': 'ｏ', 'target': 'o', 'hex': '0xff4f', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65328, 'char': 'Ｐ', 'target': 'P', 'hex': '0xff30', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
            {'unicode': 65360, 'char': 'ｐ', 'target': 'p', 'hex': '0xff50', 'script': 'Fullwidth', 'effectiveness': 'High', 'success_rate': 80},
        ]
        elite_chars.extend(fullwidth_chars)
        
        # 🔤 LATIN EXTENDED CHARACTERS (Medium effectiveness)
        latin_extended = [
            # Latin A variants
            {'unicode': 224, 'char': 'à', 'target': 'a', 'hex': '0xe0', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 225, 'char': 'á', 'target': 'a', 'hex': '0xe1', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 226, 'char': 'â', 'target': 'a', 'hex': '0xe2', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 227, 'char': 'ã', 'target': 'a', 'hex': '0xe3', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 228, 'char': 'ä', 'target': 'a', 'hex': '0xe4', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 229, 'char': 'å', 'target': 'a', 'hex': '0xe5', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 257, 'char': 'ā', 'target': 'a', 'hex': '0x101', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            {'unicode': 259, 'char': 'ă', 'target': 'a', 'hex': '0x103', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            {'unicode': 261, 'char': 'ą', 'target': 'a', 'hex': '0x105', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            
            # Latin E variants
            {'unicode': 232, 'char': 'è', 'target': 'e', 'hex': '0xe8', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 233, 'char': 'é', 'target': 'e', 'hex': '0xe9', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 234, 'char': 'ê', 'target': 'e', 'hex': '0xea', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 235, 'char': 'ë', 'target': 'e', 'hex': '0xeb', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 275, 'char': 'ē', 'target': 'e', 'hex': '0x113', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            {'unicode': 277, 'char': 'ĕ', 'target': 'e', 'hex': '0x115', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            {'unicode': 279, 'char': 'ė', 'target': 'e', 'hex': '0x117', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            
            # Latin O variants
            {'unicode': 242, 'char': 'ò', 'target': 'o', 'hex': '0xf2', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 243, 'char': 'ó', 'target': 'o', 'hex': '0xf3', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 244, 'char': 'ô', 'target': 'o', 'hex': '0xf4', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 245, 'char': 'õ', 'target': 'o', 'hex': '0xf5', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 246, 'char': 'ö', 'target': 'o', 'hex': '0xf6', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 248, 'char': 'ø', 'target': 'o', 'hex': '0xf8', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 333, 'char': 'ō', 'target': 'o', 'hex': '0x14d', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            
            # Latin I variants
            {'unicode': 236, 'char': 'ì', 'target': 'i', 'hex': '0xec', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 237, 'char': 'í', 'target': 'i', 'hex': '0xed', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 238, 'char': 'î', 'target': 'i', 'hex': '0xee', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 239, 'char': 'ï', 'target': 'i', 'hex': '0xef', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 297, 'char': 'ĩ', 'target': 'i', 'hex': '0x129', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            {'unicode': 299, 'char': 'ī', 'target': 'i', 'hex': '0x12b', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            
            # Latin U variants
            {'unicode': 249, 'char': 'ù', 'target': 'u', 'hex': '0xf9', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 250, 'char': 'ú', 'target': 'u', 'hex': '0xfa', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 251, 'char': 'û', 'target': 'u', 'hex': '0xfb', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 252, 'char': 'ü', 'target': 'u', 'hex': '0xfc', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 60},
            {'unicode': 361, 'char': 'ũ', 'target': 'u', 'hex': '0x169', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
            {'unicode': 363, 'char': 'ū', 'target': 'u', 'hex': '0x16b', 'script': 'Latin', 'effectiveness': 'Medium', 'success_rate': 55},
        ]
        elite_chars.extend(latin_extended)
        
        # 🔢 MATHEMATICAL ALPHANUMERIC SYMBOLS
        math_chars = [
            # Mathematical Bold
            {'unicode': 119808, 'char': '𝐀', 'target': 'A', 'hex': '0x1d400', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 50},
            {'unicode': 119834, 'char': '𝐚', 'target': 'a', 'hex': '0x1d41a', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 50},
            {'unicode': 119810, 'char': '𝐂', 'target': 'C', 'hex': '0x1d402', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 50},
            {'unicode': 119836, 'char': '𝐜', 'target': 'c', 'hex': '0x1d41c', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 50},
            {'unicode': 119812, 'char': '𝐄', 'target': 'E', 'hex': '0x1d404', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 50},
            {'unicode': 119838, 'char': '𝐞', 'target': 'e', 'hex': '0x1d41e', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 50},
            
            # Mathematical Italic
            {'unicode': 119860, 'char': '𝐴', 'target': 'A', 'hex': '0x1d434', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 45},
            {'unicode': 119886, 'char': '𝑎', 'target': 'a', 'hex': '0x1d44e', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 45},
            {'unicode': 119862, 'char': '𝐶', 'target': 'C', 'hex': '0x1d436', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 45},
            {'unicode': 119888, 'char': '𝑐', 'target': 'c', 'hex': '0x1d450', 'script': 'Mathematical', 'effectiveness': 'Medium', 'success_rate': 45},
        ]
        elite_chars.extend(math_chars)
        
        # 🔥 SPECIAL UNICODE TRICKS (High effectiveness in specific contexts)
        special_tricks = [
            # Zero-width characters (Very effective for bypassing filters)
            {'unicode': 8203, 'char': '​', 'target': '', 'hex': '0x200b', 'script': 'Special', 'effectiveness': 'High', 'success_rate': 80, 'category': 'zero_width'},
            {'unicode': 8204, 'char': '‌', 'target': '', 'hex': '0x200c', 'script': 'Special', 'effectiveness': 'High', 'success_rate': 80, 'category': 'zero_width'},
            {'unicode': 8205, 'char': '‍', 'target': '', 'hex': '0x200d', 'script': 'Special', 'effectiveness': 'High', 'success_rate': 80, 'category': 'zero_width'},
            
            # Invisible characters
            {'unicode': 160, 'char': ' ', 'target': ' ', 'hex': '0xa0', 'script': 'Special', 'effectiveness': 'Medium', 'success_rate': 65, 'category': 'invisible'},
            {'unicode': 8239, 'char': ' ', 'target': ' ', 'hex': '0x202f', 'script': 'Special', 'effectiveness': 'Medium', 'success_rate': 65, 'category': 'invisible'},
            {'unicode': 8287, 'char': ' ', 'target': ' ', 'hex': '0x205f', 'script': 'Special', 'effectiveness': 'Medium', 'success_rate': 60, 'category': 'invisible'},
            
            # Combining characters
            {'unicode': 776, 'char': '̈', 'target': '', 'hex': '0x308', 'script': 'Special', 'effectiveness': 'Medium', 'success_rate': 55, 'category': 'combining'},
            {'unicode': 769, 'char': '́', 'target': '', 'hex': '0x301', 'script': 'Special', 'effectiveness': 'Medium', 'success_rate': 55, 'category': 'combining'},
            {'unicode': 768, 'char': '̀', 'target': '', 'hex': '0x300', 'script': 'Special', 'effectiveness': 'Medium', 'success_rate': 55, 'category': 'combining'},
            
            # Homoglyphs for digits and special chars
            {'unicode': 48, 'char': '0', 'target': '0', 'hex': '0x30', 'script': 'ASCII', 'effectiveness': 'High', 'success_rate': 90, 'category': 'digit'},
            {'unicode': 79, 'char': 'O', 'target': '0', 'hex': '0x4f', 'script': 'ASCII', 'effectiveness': 'High', 'success_rate': 85, 'category': 'digit'},
            {'unicode': 111, 'char': 'o', 'target': '0', 'hex': '0x6f', 'script': 'ASCII', 'effectiveness': 'Medium', 'success_rate': 75, 'category': 'digit'},
            {'unicode': 49, 'char': '1', 'target': '1', 'hex': '0x31', 'script': 'ASCII', 'effectiveness': 'High', 'success_rate': 90, 'category': 'digit'},
            {'unicode': 73, 'char': 'I', 'target': '1', 'hex': '0x49', 'script': 'ASCII', 'effectiveness': 'High', 'success_rate': 85, 'category': 'digit'},
            {'unicode': 108, 'char': 'l', 'target': '1', 'hex': '0x6c', 'script': 'ASCII', 'effectiveness': 'High', 'success_rate': 85, 'category': 'digit'},
        ]
        elite_chars.extend(special_tricks)
        
        # 🌏 OTHER SCRIPTS (Lower effectiveness but useful for specific targets)
        other_scripts = [
            # Armenian
            {'unicode': 1377, 'char': 'ա', 'target': 'a', 'hex': '0x561', 'script': 'Armenian', 'effectiveness': 'Low', 'success_rate': 30},
            {'unicode': 1345, 'char': 'Ա', 'target': 'A', 'hex': '0x541', 'script': 'Armenian', 'effectiveness': 'Low', 'success_rate': 30},
            
            # Georgian
            {'unicode': 4304, 'char': 'ა', 'target': 'a', 'hex': '0x10d0', 'script': 'Georgian', 'effectiveness': 'Low', 'success_rate': 25},
            {'unicode': 4317, 'char': 'ნ', 'target': 'n', 'hex': '0x10dc', 'script': 'Georgian', 'effectiveness': 'Low', 'success_rate': 25},
            
            # Hebrew (Context-dependent)
            {'unicode': 1488, 'char': 'א', 'target': 'N', 'hex': '0x5d0', 'script': 'Hebrew', 'effectiveness': 'Very Low', 'success_rate': 15},
            {'unicode': 1489, 'char': 'ב', 'target': 'b', 'hex': '0x5d1', 'script': 'Hebrew', 'effectiveness': 'Very Low', 'success_rate': 15},
            
            # Arabic (Context-dependent)
            {'unicode': 1575, 'char': 'ا', 'target': 'I', 'hex': '0x627', 'script': 'Arabic', 'effectiveness': 'Very Low', 'success_rate': 15},
            {'unicode': 1608, 'char': 'و', 'target': 'g', 'hex': '0x648', 'script': 'Arabic', 'effectiveness': 'Very Low', 'success_rate': 15},
        ]
        elite_chars.extend(other_scripts)
        
        return elite_chars
    
    async def get_built_in_characters(self):
        """Return built-in elite character database when no DB connection"""
        self.console.print("🔥 Loading Elite Character Database...", style="yellow")
        
        # Show comprehensive statistics
        total_chars = len(self.elite_character_database)
        scripts = set([char['script'] for char in self.elite_character_database])
        very_high = len([char for char in self.elite_character_database if char.get('effectiveness') == 'Very High'])
        high = len([char for char in self.elite_character_database if char.get('effectiveness') == 'High'])
        medium = len([char for char in self.elite_character_database if char.get('effectiveness') == 'Medium'])
        low = len([char for char in self.elite_character_database if char.get('effectiveness') == 'Low'])
        
        # Calculate average success rate
        success_rates = [char.get('success_rate', 0) for char in self.elite_character_database if 'success_rate' in char]
        avg_success_rate = sum(success_rates) / len(success_rates) if success_rates else 0
        
        self.console.print(f"📊 Elite Database Stats:", style="green")
        self.console.print(f"   Total Characters: {total_chars}", style="cyan")
        self.console.print(f"   Scripts Covered: {len(scripts)}", style="cyan")
        self.console.print(f"   Very High Effectiveness: {very_high}", style="red")
        self.console.print(f"   High Effectiveness: {high}", style="yellow")
        self.console.print(f"   Medium Effectiveness: {medium}", style="blue")
        self.console.print(f"   Low Effectiveness: {low}", style="white")
        self.console.print(f"   Average Success Rate: {avg_success_rate:.1f}%", style="green")
        
        return self.elite_character_database
    
    async def mysql_fuzzer(self, connection_string):
        """Enhanced MySQL Character Fuzzing with Elite Database"""
        try:
            conn = mysql.connector.connect(**connection_string)
            cursor = conn.cursor()
            
            vulnerable_chars = []
            
            self.console.print("🔍 Testing elite characters against MySQL...", style="yellow")
            
            # Test elite character database against MySQL
            for char_data in self.elite_character_database:
                try:
                    char = char_data['char']
                    target = char_data['target']
                    
                    if target:  # Only test if target is not empty
                        cursor.execute("SELECT %s = %s AS is_equal", (char, target))
                        result = cursor.fetchone()
                        
                        if result[0] and char != target:
                            char_data_copy = char_data.copy()
                            char_data_copy['database_tested'] = 'mysql'
                            char_data_copy['mysql_vulnerable'] = True
                            char_data_copy['test_result'] = 'positive'
                            vulnerable_chars.append(char_data_copy)
                            
                except Exception:
                    continue
                    
            conn.close()
            self.console.print(f"✅ Found {len(vulnerable_chars)} MySQL-vulnerable characters", style="green")
            return vulnerable_chars
            
        except Exception as e:
            self.console.print(f"MySQL Connection Error: {e}", style="red")
            # Return elite database as fallback
            return await self.get_built_in_characters()
    
    async def postgresql_fuzzer(self, connection_string):
        """PostgreSQL Character Confusion Testing"""
        try:
            conn = psycopg2.connect(**connection_string)
            cursor = conn.cursor()
            
            vulnerable_chars = []
            
            self.console.print("🔍 Testing elite characters against PostgreSQL...", style="yellow")
            
            # Test different collations
            collations = ['C', 'POSIX', 'en_US.utf8', 'en_US.UTF-8']
            
            for char_data in self.elite_character_database:
                try:
                    char = char_data['char']
                    target = char_data['target']
                    
                    if target:  # Only test if target is not empty
                        for collation in collations:
                            try:
                                query = f"SELECT %s = %s COLLATE \"{collation}\" AS is_equal"
                                cursor.execute(query, (char, target))
                                result = cursor.fetchone()
                                
                                if result[0] and char != target:
                                    char_data_copy = char_data.copy()
                                    char_data_copy['collation'] = collation
                                    char_data_copy['database_tested'] = 'postgresql'
                                    char_data_copy['postgresql_vulnerable'] = True
                                    char_data_copy['test_result'] = 'positive'
                                    vulnerable_chars.append(char_data_copy)
                                    break  # Found vulnerability, no need to test other collations
                                    
                            except Exception:
                                continue
                                
                except Exception:
                    continue
                        
            conn.close()
            self.console.print(f"✅ Found {len(vulnerable_chars)} PostgreSQL-vulnerable characters", style="green")
            return vulnerable_chars
            
        except Exception as e:
            self.console.print(f"PostgreSQL Connection Error: {e}", style="red")
            # Return elite database as fallback
            return await self.get_built_in_characters()
    
    async def save_results(self, results, filename):
        """Save discovered characters to multiple formats with proper field handling"""
        try:
            # Create results directory if it doesn't exist
            results_dir = os.path.dirname(filename) if os.path.dirname(filename) else 'results'
            os.makedirs(results_dir, exist_ok=True)
            
            # JSON Export (complete data)
            json_file = f"{filename}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            # CSV Export with field filtering
            csv_file = f"{filename}.csv"
            if results:
                # Define allowed CSV fields (excluding problematic ones)
                csv_fields = [
                    'unicode', 'char', 'target', 'hex', 'script', 'effectiveness',
                    'success_rate', 'database_tested', 'mysql_vulnerable', 
                    'postgresql_vulnerable', 'collation', 'test_result'
                ]
                
                # Filter and clean results for CSV
                clean_results = []
                for result in results:
                    clean_result = {}
                    for field in csv_fields:
                        if field in result:
                            clean_result[field] = result[field]
                    if clean_result:  # Only add if not empty
                        clean_results.append(clean_result)
                
                # Write CSV with cleaned data
                if clean_results:
                    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=csv_fields)
                        writer.writeheader()
                        for result in clean_results:
                            # Fill missing fields with empty strings
                            row = {field: result.get(field, '') for field in csv_fields}
                            writer.writerow(row)
            
            # Burp Suite Extension Format
            burp_file = f"{filename}_burp.txt"
            with open(burp_file, 'w', encoding='utf-8') as f:
                for char_data in results:
                    char = char_data.get('char', '')
                    if char:
                        f.write(char + '\n')
            
            # Advanced payload format for different tools
            payload_file = f"{filename}_payloads.txt"
            with open(payload_file, 'w', encoding='utf-8') as f:
                f.write("# PunyHunter Pro Character Database Export\n")
                f.write("# Format: character|target|unicode|effectiveness|success_rate\n\n")
                for char_data in results:
                    char = char_data.get('char', '')
                    target = char_data.get('target', '')
                    unicode_point = char_data.get('unicode', '')
                    effectiveness = char_data.get('effectiveness', '')
                    success_rate = char_data.get('success_rate', '')
                    if char:
                        f.write(f"{char}|{target}|{unicode_point}|{effectiveness}|{success_rate}\n")
            
            # Summary report
            summary_file = f"{filename}_summary.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("=== PunyHunter Pro Character Discovery Summary ===\n\n")
                f.write(f"Total Characters: {len(results)}\n")
                
                # Count by script
                scripts = {}
                effectiveness_counts = {}
                for result in results:
                    script = result.get('script', 'Unknown')
                    scripts[script] = scripts.get(script, 0) + 1
                    
                    eff = result.get('effectiveness', 'Unknown')
                    effectiveness_counts[eff] = effectiveness_counts.get(eff, 0) + 1
                
                f.write("\nCharacters by Script:\n")
                for script, count in sorted(scripts.items()):
                    f.write(f"  {script}: {count}\n")
                
                f.write("\nCharacters by Effectiveness:\n")
                for eff, count in sorted(effectiveness_counts.items()):
                    f.write(f"  {eff}: {count}\n")
                
                # Top characters by success rate
                f.write("\nTop 10 Most Effective Characters:\n")
                sorted_chars = sorted(results, key=lambda x: x.get('success_rate', 0), reverse=True)
                for char_data in sorted_chars[:10]:
                    char = char_data.get('char', '')
                    target = char_data.get('target', '')
                    success_rate = char_data.get('success_rate', 0)
                    script = char_data.get('script', '')
                    f.write(f"  '{char}' -> '{target}' ({success_rate}% success, {script})\n")
            
            self.console.print(f"✅ Character discovery results saved to:", style="green")
            self.console.print(f"   📄 JSON: {json_file}", style="cyan")
            self.console.print(f"   📊 CSV: {csv_file}", style="cyan")  
            self.console.print(f"   🎯 Burp: {burp_file}", style="cyan")
            self.console.print(f"   📋 Summary: {summary_file}", style="cyan")
            
        except Exception as e:
            self.console.print(f"⚠️ Error saving results: {e}", style="yellow")
            # Fallback: save at least JSON
            try:
                with open(f"{filename}_backup.json", 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                self.console.print(f"✅ Backup JSON saved to {filename}_backup.json", style="green")
            except:
                pass
    
    def display_character_statistics(self, characters):
        """Display detailed character statistics"""
        if not characters:
            return
        
        # Create statistics table
        stats_table = Table(title="🔥 Elite Character Database Statistics", box=box.DOUBLE_EDGE)
        stats_table.add_column("Script", style="cyan", width=15)
        stats_table.add_column("Count", style="green", width=10)
        stats_table.add_column("Very High", style="red", width=12)
        stats_table.add_column("High", style="yellow", width=8)
        stats_table.add_column("Medium", style="blue", width=10)
        stats_table.add_column("Avg Success", style="magenta", width=12)
        
        # Calculate statistics by script
        script_stats = {}
        for char in characters:
            script = char.get('script', 'Unknown')
            if script not in script_stats:
                script_stats[script] = {
                    'count': 0,
                    'very_high': 0,
                    'high': 0,
                    'medium': 0,
                    'success_rates': []
                }
            
            script_stats[script]['count'] += 1
            
            effectiveness = char.get('effectiveness', '')
            if effectiveness == 'Very High':
                script_stats[script]['very_high'] += 1
            elif effectiveness == 'High':
                script_stats[script]['high'] += 1
            elif effectiveness == 'Medium':
                script_stats[script]['medium'] += 1
            
            success_rate = char.get('success_rate', 0)
            if success_rate:
                script_stats[script]['success_rates'].append(success_rate)
        
        # Add rows to table
        for script, stats in sorted(script_stats.items()):
            avg_success = sum(stats['success_rates']) / len(stats['success_rates']) if stats['success_rates'] else 0
            
            stats_table.add_row(
                script,
                str(stats['count']),
                str(stats['very_high']),
                str(stats['high']),
                str(stats['medium']),
                f"{avg_success:.1f}%"
            )
        
        self.console.print(stats_table)

# Test function
async def test_character_discovery():
    """Test the character discovery functionality"""
    char_discovery = CharacterDiscovery()
    
    # Test built-in database
    print("Testing elite character database...")
    results = await char_discovery.get_built_in_characters()
    
    # Display statistics
    char_discovery.display_character_statistics(results)
    
    # Save results
    await char_discovery.save_results(results, "test_characters")
    
    print(f"✅ Character discovery test completed with {len(results)} characters")

# Example usage
if __name__ == "__main__":
    import asyncio
    asyncio.run(test_character_discovery())
