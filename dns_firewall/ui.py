
"""
.. module:: dns_firewall.ui
   :synopsis: Local DNS firewall Gtk UI

"""

# Released under AGPLv3+ license, see LICENSE

from datetime import datetime
from gi.repository import Gtk, Gdk, GObject
from pkg_resources import resource_filename
from logging import getLogger
import gevent
import cairo
import os
import sys

Gtk.Widget.__enter__ = lambda self, *a, **kw: self
Gtk.Widget.__exit__ = lambda *a, **kw: None

ACTION_COLOR_MAP = dict(accept='green', drop='red', nxdomain='orange',
                        default='orange')
NUM_LOG_ROWS = 100

log = getLogger()


def _pos(menu, icon):
    return (Gtk.StatusIcon.position_menu(menu, icon))


def get_resource(fn):
    if 'DEVELOPMENT' in os.environ:
        p = 'dns_firewall'
    else:
        p = resource_filename(__name__, '.')

    ap = os.path.abspath(p)
    return os.path.join(ap, 'data', fn)


class PopupMenu(object):

    def __init__(self, icon):
        self._status_icon = icon
        with Gtk.Menu() as menu:
            with Gtk.MenuItem('Exit') as item:
                menu.append(item)
                item.connect('activate', self._status_icon.exit)

            menu.show_all()
            self._menu = menu

    def popup(self, widget, button, time):
        self._menu.popup(None, None, _pos, self._status_icon._icon, button,
                         time)


class LogsWindow(Gtk.Window):

    def __init__(self, trayicon):
        Gtk.Window.__init__(self, title="DNS firewall logs")
        self.set_style()
        self._trayicon = trayicon
        self.set_border_width(10)

        with Gtk.Box(spacing=6) as hbox:
            self.add(hbox)

            with Gtk.VBox(spacing=6) as vbox:
                hbox.add(vbox)

                with Gtk.Button('Close') as closebtn:
                    vbox.pack_start(closebtn, True, True, 0)
                    closebtn.connect('clicked', lambda _: self.hide())

                with Gtk.Button('Exit') as closebtn:
                    vbox.pack_start(closebtn, True, True, 0)
                    closebtn.connect('clicked', self._trayicon.exit)

                with Gtk.ScrolledWindow() as scrollw:
                    hbox.pack_start(scrollw, True, True, 0)
                    scrollw.set_size_request(250, 150)
                    self._scrolled_window = scrollw

                    with Gtk.Grid() as grid:
                        scrollw.add(grid)
                        self._logs_grid = grid

                vbox.connect('size-allocate', self._adjust_scrolling_window)

    def _adjust_scrolling_window(self, widget, event, data=None):
        adj = self._scrolled_window.get_vadjustment()
        adj.set_value(adj.get_upper() - adj.get_page_size())

    def toggle_visibility(self, *a):
        if self.is_visible():
            self.hide()
        else:
            self.show_all()

    def add_log_line(self, client_program_name, q_domain, domain_filter,
                     action):
        """Add a log line to the displayed list"""
        color = ACTION_COLOR_MAP.get(action, ACTION_COLOR_MAP['default'])
        tstamp = datetime.now().strftime('%H:%M:%S')
        row_num = len(self._logs_grid) / 4

        items = (tstamp, client_program_name, q_domain, action)
        for col_num, i in enumerate(items):
            with Gtk.Label(" %s " % i, xalign=0) as label:
                label.set_name("%s-background" % color)
                self._logs_grid.attach(label, col_num, row_num, 1, 1)

        if row_num > NUM_LOG_ROWS:
            self._logs_grid.remove_row(0)

        self._logs_grid.show_all()
        self._logs_grid.queue_draw()

    def set_style(self):
        style_provider = Gtk.CssProvider()

        css = """
        #red-background {
            background-color: #ffeeee;
        }
        #orange-background {
            background-color: #fff3d7;
        }
        #green-background {
            background-color: #eeffee;
        }
        """

        style_provider.load_from_data(css)

        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            style_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def _on_close(self, *a):
        self._window.close()


class TrayIcon(object):
    def __init__(self):

        self._menu_popup = PopupMenu(self)
        self._logs_window = LogsWindow(self)

        self._icon_cache = {}
        self._blinker_flags = {}
        self._icon = Gtk.StatusIcon()
        self._icon.connect('activate', self._logs_window.toggle_visibility)
        self._icon.connect('popup-menu', self._menu_popup.popup)
        self._icon.set_visible(True)
        self.set_icon()
        # self._logs_window.toggle_visibility()  # development

    def set_tooltip_text(self, text):
        self._icon.set_tooltip_text(text)

    def pos(self, menu, icon):
        return (Gtk.StatusIcon.position_menu(menu, icon))

    def set_icon(self):
        self._icon.set_from_pixbuf(self.generate_icon(self._blinker_flags))

    def set_blinker(self, color):
        try:
            GObject.source_remove(self._blinker_flags[color])
            redraw_needed = False
        except KeyError:
            redraw_needed = True

        t_id = GObject.timeout_add(300, self._reset_blinker, color)
        self._blinker_flags[color] = t_id
        if redraw_needed:
            self.set_icon()

    def _reset_blinker(self, color):
        try:
            GObject.source_remove(self._blinker_flags[color])
            del(self._blinker_flags[color])
        except KeyError:
            pass

        self.set_icon()

    def generate_icon(self, flags):
        """Generate tray icon based on the current set of active flags
        """
        flag_names = ('red', 'orange', 'green')
        flags = tuple(f in flags for f in flag_names)
        try:
            return self._icon_cache[flags]
        except KeyError:
            pass

        size = 64
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
        ctx = cairo.Context(surface)

        bkg = cairo.ImageSurface.create_from_png(get_resource('bkg.png'))
        ctx.set_source_surface(bkg, 0, 0)
        ctx.paint()

        for status, name in zip(flags, flag_names):
            if status:
                fn = get_resource("%s.png" % name)
                img = cairo.ImageSurface.create_from_png(fn)
                ctx.set_source_surface(img, 0, 0)
                ctx.paint()

        pb = Gdk.pixbuf_get_from_surface(
            ctx.get_target(),
            0,
            0,
            ctx.get_target().get_width(),
            ctx.get_target().get_height()
        )
        self._icon_cache[flags] = pb
        return pb

    def run(self):

        GObject.timeout_add(100, self._idle, priority=GObject.PRIORITY_HIGH)

        while True:
            Gtk.main_iteration()
            gevent.sleep(.001)

    def _idle(self):
        gevent.sleep()
        return True

    def start(self):
        gevent.Greenlet.spawn(self.run)

    def exit(self, *a):
        """Close the applet"""
        sys.exit()

    def add_log_message(self, client_program_name, q_domain, domain_filter,
                        action):
        """Add log message to the logs window"""
        self._logs_window.add_log_line(client_program_name, q_domain,
                                       domain_filter, action)
        color = ACTION_COLOR_MAP.get(action, ACTION_COLOR_MAP['default'])
        GObject.timeout_add(1000, self.set_blinker, color)
