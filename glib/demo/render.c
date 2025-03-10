/*
 * Copyright (C) 2007 Carlos Garcia Campos  <carlosgc@gnome.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "config.h"

#include <gtk/gtk.h>
#include <cairo.h>

#include "render.h"

typedef struct
{
    PopplerDocument *doc;

    /* Properties */
    gint page;
    gdouble scale;
    gint rotate;
    GdkRectangle slice;
    gboolean printing;
    gboolean highlight;

    GtkWidget *swindow;
    GtkWidget *darea;
    GtkWidget *slice_x;
    GtkWidget *slice_y;
    GtkWidget *slice_w;
    GtkWidget *slice_h;
    GtkWidget *timer_label;

    cairo_surface_t *surface;
} PgdRenderDemo;

static void pgd_render_free(PgdRenderDemo *demo)
{
    if (!demo) {
        return;
    }

    if (demo->doc) {
        g_object_unref(demo->doc);
        demo->doc = NULL;
    }

    if (demo->surface) {
        cairo_surface_destroy(demo->surface);
        demo->surface = NULL;
    }

    g_free(demo);
}

static gboolean pgd_render_drawing_area_draw(GtkWidget *area, cairo_t *cr, PgdRenderDemo *demo)
{
    if (!demo->surface) {
        return FALSE;
    }

    cairo_set_source_surface(cr, demo->surface, 0, 0);
    cairo_paint(cr);

    return TRUE;
}

static void pgd_render_start(GtkButton *button, PgdRenderDemo *demo)
{
    PopplerPage *page;
    gdouble page_width, page_height;
    gdouble width, height;
    gint x, y;
    gchar *str;
    GTimer *timer;
    cairo_t *cr;

    page = poppler_document_get_page(demo->doc, demo->page);
    if (!page) {
        return;
    }

    if (demo->surface) {
        cairo_surface_destroy(demo->surface);
    }
    demo->surface = NULL;

    poppler_page_get_size(page, &page_width, &page_height);

    if (demo->rotate == 0 || demo->rotate == 180) {
        width = demo->slice.width * demo->scale;
        height = demo->slice.height * demo->scale;
        x = demo->slice.x * demo->scale;
        y = demo->slice.y * demo->scale;
    } else {
        width = demo->slice.height * demo->scale;
        height = demo->slice.width * demo->scale;
        x = demo->slice.y * demo->scale;
        y = demo->slice.x * demo->scale;
    }

    timer = g_timer_new();
    demo->surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
    cr = cairo_create(demo->surface);

    cairo_save(cr);
    switch (demo->rotate) {
    case 90:
        cairo_translate(cr, x + width, -y);
        break;
    case 180:
        cairo_translate(cr, x + width, y + height);
        break;
    case 270:
        cairo_translate(cr, -x, y + height);
        break;
    default:
        cairo_translate(cr, -x, -y);
    }

    if (demo->scale != 1.0) {
        cairo_scale(cr, demo->scale, demo->scale);
    }

    if (demo->rotate != 0) {
        cairo_rotate(cr, demo->rotate * G_PI / 180.0);
    }

    if (demo->printing) {
        poppler_page_render_for_printing(page, cr);
    } else if (demo->highlight) {
        poppler_page_render(page, cr);
    } else {
        poppler_page_render_full(page, cr, FALSE, POPPLER_RENDER_ANNOTS_ALL & (~POPPLER_RENDER_ANNOTS_HIGHLIGHT));
    }
    cairo_restore(cr);

    cairo_set_operator(cr, CAIRO_OPERATOR_DEST_OVER);
    cairo_set_source_rgb(cr, 1., 1., 1.);
    cairo_paint(cr);

    g_timer_stop(timer);

    cairo_destroy(cr);
    g_object_unref(page);

    str = g_strdup_printf("<i>Page rendered in %.4f seconds</i>", g_timer_elapsed(timer, NULL));
    gtk_label_set_markup(GTK_LABEL(demo->timer_label), str);
    g_free(str);

    g_timer_destroy(timer);

    gtk_widget_set_size_request(demo->darea, width, height);
    gtk_widget_queue_draw(demo->darea);
}

static void pgd_render_slice_selector_setup(PgdRenderDemo *demo)
{
    PopplerPage *page;
    gdouble width, height;

    page = poppler_document_get_page(demo->doc, demo->page);
    if (!page) {
        return;
    }

    poppler_page_get_size(page, &width, &height);

    gtk_spin_button_set_range(GTK_SPIN_BUTTON(demo->slice_x), 0, width);
    gtk_spin_button_set_range(GTK_SPIN_BUTTON(demo->slice_y), 0, height);
    gtk_spin_button_set_range(GTK_SPIN_BUTTON(demo->slice_w), 0, width);
    gtk_spin_button_set_range(GTK_SPIN_BUTTON(demo->slice_h), 0, height);

    gtk_spin_button_set_value(GTK_SPIN_BUTTON(demo->slice_x), 0);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(demo->slice_y), 0);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(demo->slice_w), width);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(demo->slice_h), height);

    g_object_unref(page);
}

static void pgd_render_page_selector_value_changed(GtkSpinButton *spinbutton, PgdRenderDemo *demo)
{
    demo->page = (gint)gtk_spin_button_get_value(spinbutton) - 1;
    pgd_render_slice_selector_setup(demo);
}

static void pgd_render_scale_selector_value_changed(GtkSpinButton *spinbutton, PgdRenderDemo *demo)
{
    demo->scale = gtk_spin_button_get_value(spinbutton);
}

static void pgd_render_rotate_selector_changed(GtkComboBox *combobox, PgdRenderDemo *demo)
{
    demo->rotate = gtk_combo_box_get_active(combobox) * 90;
}

static void pgd_render_printing_selector_changed(GtkToggleButton *tooglebutton, PgdRenderDemo *demo)
{
    demo->printing = gtk_toggle_button_get_active(tooglebutton);
}

static void pgd_render_highlight_selector_changed(GtkToggleButton *tooglebutton, PgdRenderDemo *demo)
{
    demo->highlight = gtk_toggle_button_get_active(tooglebutton);
}

static void pgd_render_slice_selector_value_changed(GtkSpinButton *spinbutton, PgdRenderDemo *demo)
{
    demo->slice.x = (gint)gtk_spin_button_get_value(GTK_SPIN_BUTTON(demo->slice_x));
    demo->slice.y = (gint)gtk_spin_button_get_value(GTK_SPIN_BUTTON(demo->slice_y));
    demo->slice.width = (gint)gtk_spin_button_get_value(GTK_SPIN_BUTTON(demo->slice_w));
    demo->slice.height = (gint)gtk_spin_button_get_value(GTK_SPIN_BUTTON(demo->slice_h));
}

GtkWidget *pgd_render_properties_selector_create(PgdRenderDemo *demo)
{
    GtkWidget *hbox, *vbox;
    GtkWidget *label;
    GtkWidget *page_hbox, *page_selector;
    GtkWidget *scale_hbox, *scale_selector;
    GtkWidget *rotate_hbox, *rotate_selector;
    GtkWidget *selector;
    GtkWidget *slice_hbox;
    GtkWidget *button;
    gint n_pages;
    gchar *str;

    n_pages = poppler_document_get_n_pages(demo->doc);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
    gtk_widget_show(hbox);

    page_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("Page:");
    gtk_box_pack_start(GTK_BOX(page_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    page_selector = gtk_spin_button_new_with_range(1, n_pages, 1);
    g_signal_connect(G_OBJECT(page_selector), "value-changed", G_CALLBACK(pgd_render_page_selector_value_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(page_hbox), page_selector, TRUE, TRUE, 0);
    gtk_widget_show(page_selector);

    str = g_strdup_printf("of %d", n_pages);
    label = gtk_label_new(str);
    gtk_box_pack_start(GTK_BOX(page_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);
    g_free(str);

    gtk_box_pack_start(GTK_BOX(hbox), page_hbox, FALSE, TRUE, 0);
    gtk_widget_show(page_hbox);

    scale_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("Scale:");
    gtk_box_pack_start(GTK_BOX(scale_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    scale_selector = gtk_spin_button_new_with_range(0, 10.0, 0.1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(scale_selector), 1.0);
    g_signal_connect(G_OBJECT(scale_selector), "value-changed", G_CALLBACK(pgd_render_scale_selector_value_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(scale_hbox), scale_selector, TRUE, TRUE, 0);
    gtk_widget_show(scale_selector);

    gtk_box_pack_start(GTK_BOX(hbox), scale_hbox, FALSE, TRUE, 0);
    gtk_widget_show(scale_hbox);

    rotate_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("Rotate:");
    gtk_box_pack_start(GTK_BOX(rotate_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    rotate_selector = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rotate_selector), "0");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rotate_selector), "90");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rotate_selector), "180");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rotate_selector), "270");
    gtk_combo_box_set_active(GTK_COMBO_BOX(rotate_selector), 0);
    g_signal_connect(G_OBJECT(rotate_selector), "changed", G_CALLBACK(pgd_render_rotate_selector_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(rotate_hbox), rotate_selector, TRUE, TRUE, 0);
    gtk_widget_show(rotate_selector);

    gtk_box_pack_start(GTK_BOX(hbox), rotate_hbox, FALSE, TRUE, 0);
    gtk_widget_show(rotate_hbox);

    selector = gtk_check_button_new_with_label("Printing");
    g_signal_connect(selector, "toggled", G_CALLBACK(pgd_render_printing_selector_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(hbox), selector, FALSE, TRUE, 0);
    gtk_widget_show(selector);

    selector = gtk_check_button_new_with_label("Render highlight annots");
    g_signal_connect(selector, "toggled", G_CALLBACK(pgd_render_highlight_selector_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(hbox), selector, FALSE, TRUE, 0);
    gtk_widget_show(selector);

    hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
    gtk_widget_show(hbox);

    slice_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("x:");
    gtk_box_pack_start(GTK_BOX(slice_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    demo->slice_x = gtk_spin_button_new_with_range(0, 0, 1.0);
    g_signal_connect(G_OBJECT(demo->slice_x), "value-changed", G_CALLBACK(pgd_render_slice_selector_value_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(slice_hbox), demo->slice_x, TRUE, TRUE, 0);
    gtk_widget_show(demo->slice_x);

    gtk_box_pack_start(GTK_BOX(hbox), slice_hbox, FALSE, TRUE, 0);
    gtk_widget_show(slice_hbox);

    slice_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("y:");
    gtk_box_pack_start(GTK_BOX(slice_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    demo->slice_y = gtk_spin_button_new_with_range(0, 0, 1.0);
    g_signal_connect(G_OBJECT(demo->slice_y), "value-changed", G_CALLBACK(pgd_render_slice_selector_value_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(slice_hbox), demo->slice_y, TRUE, TRUE, 0);
    gtk_widget_show(demo->slice_y);

    gtk_box_pack_start(GTK_BOX(hbox), slice_hbox, FALSE, TRUE, 0);
    gtk_widget_show(slice_hbox);

    slice_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("width:");
    gtk_box_pack_start(GTK_BOX(slice_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    demo->slice_w = gtk_spin_button_new_with_range(0, 0, 1.0);
    g_signal_connect(G_OBJECT(demo->slice_w), "value-changed", G_CALLBACK(pgd_render_slice_selector_value_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(slice_hbox), demo->slice_w, TRUE, TRUE, 0);
    gtk_widget_show(demo->slice_w);

    gtk_box_pack_start(GTK_BOX(hbox), slice_hbox, FALSE, TRUE, 0);
    gtk_widget_show(slice_hbox);

    slice_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    label = gtk_label_new("height:");
    gtk_box_pack_start(GTK_BOX(slice_hbox), label, TRUE, TRUE, 0);
    gtk_widget_show(label);

    demo->slice_h = gtk_spin_button_new_with_range(0, 0, 1.0);
    g_signal_connect(G_OBJECT(demo->slice_h), "value-changed", G_CALLBACK(pgd_render_slice_selector_value_changed), (gpointer)demo);
    gtk_box_pack_start(GTK_BOX(slice_hbox), demo->slice_h, TRUE, TRUE, 0);
    gtk_widget_show(demo->slice_h);

    gtk_box_pack_start(GTK_BOX(hbox), slice_hbox, FALSE, TRUE, 0);
    gtk_widget_show(slice_hbox);

    pgd_render_slice_selector_setup(demo);

    button = gtk_button_new_with_label("Render");
    g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(pgd_render_start), (gpointer)demo);
    gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, TRUE, 0);
    gtk_widget_show(button);

    demo->timer_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(demo->timer_label), "<i>No page rendered</i>");
    g_object_set(G_OBJECT(demo->timer_label), "xalign", 1.0, NULL);
    gtk_box_pack_end(GTK_BOX(vbox), demo->timer_label, FALSE, TRUE, 0);
    gtk_widget_show(demo->timer_label);

    return vbox;
}

GtkWidget *pgd_render_create_widget(PopplerDocument *document)
{
    PgdRenderDemo *demo;
    GtkWidget *vbox, *hbox;

    demo = g_new0(PgdRenderDemo, 1);

    demo->doc = g_object_ref(document);
    demo->scale = 1.0;

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    hbox = pgd_render_properties_selector_create(demo);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 6);
    gtk_widget_show(hbox);

    demo->darea = gtk_drawing_area_new();
    g_signal_connect(G_OBJECT(demo->darea), "draw", G_CALLBACK(pgd_render_drawing_area_draw), (gpointer)demo);

    demo->swindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(demo->swindow), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(demo->swindow), demo->darea);
    gtk_widget_show(demo->darea);

    gtk_box_pack_start(GTK_BOX(vbox), demo->swindow, TRUE, TRUE, 0);
    gtk_widget_show(demo->swindow);

    g_object_weak_ref(G_OBJECT(demo->swindow), (GWeakNotify)pgd_render_free, (gpointer)demo);

    return vbox;
}
