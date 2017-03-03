TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    tcp.c

HEADERS += \
    tcp.h

LIBS +=  -lcrypto
