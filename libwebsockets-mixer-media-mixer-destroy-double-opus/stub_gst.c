/* Empty GStreamer function stubs for linking mixer-media.c
 * None of these are called at runtime — all GStreamer pointers are NULL */
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <stdarg.h>

void gst_init(int *a, char ***b) {}
gboolean gst_is_initialized(void) { return 0; }
GstElement *gst_parse_launch(const gchar *d, GError **e) { return NULL; }
GstElement *gst_element_factory_make(const gchar *t, const gchar *n) { return NULL; }
GstStateChangeReturn gst_element_set_state(GstElement *e, GstState s) { return GST_STATE_CHANGE_SUCCESS; }
gboolean gst_element_sync_state_with_parent(GstElement *e) { return 1; }
GstStateChangeReturn gst_element_get_state(GstElement *e, GstState *s, GstState *p, GstClockTime t) { return GST_STATE_CHANGE_SUCCESS; }
GstBus *gst_element_get_bus(GstElement *e) { return NULL; }
guint gst_bus_add_watch(GstBus *b, GstBusFunc f, gpointer d) { return 0; }
GstMessage *gst_bus_pop(GstBus *b) { return NULL; }
void gst_message_unref(GstMessage *m) {}
void gst_message_parse_error(GstMessage *m, GError **e, gchar **d) {}
void gst_message_parse_warning(GstMessage *m, GError **e, gchar **d) {}
void gst_message_parse_state_changed(GstMessage *m, GstState *o, GstState *n, GstState *p) {}
void gst_message_parse_qos(GstMessage *m, gboolean *l, guint64 *r, guint64 *s, guint64 *t, guint64 *d) {}
void gst_message_parse_qos_stats(GstMessage *m, GstFormat *f, guint64 *p, guint64 *d) {}
GstPad *gst_element_get_static_pad(GstElement *e, const gchar *n) { return NULL; }
GstPad *gst_element_request_pad_simple(GstElement *e, const gchar *n) { return NULL; }
void gst_element_release_request_pad(GstElement *e, GstPad *p) {}
GstPadLinkReturn gst_pad_link(GstPad *s, GstPad *d) { return GST_PAD_LINK_OK; }
guint gst_pad_add_probe(GstPad *p, GstPadProbeType t, GstPadProbeCallback c, gpointer d, void *x) { return 0; }
gchar *gst_pad_get_name(GstPad *p) { return NULL; }
GstBuffer *gst_buffer_new_allocate(void *a, size_t s, void *p) { return NULL; }
void gst_buffer_fill(GstBuffer *b, size_t o, const void *s, size_t sz) {}
gboolean gst_buffer_map(GstBuffer *b, GstMapInfo *i, GstMapFlags f) { return 0; }
void gst_buffer_unmap(GstBuffer *b, GstMapInfo *i) {}
size_t gst_buffer_get_size(GstBuffer *b) { return 0; }
GstBuffer *gst_sample_get_buffer(GstSample *s) { return NULL; }
void gst_sample_unref(GstSample *s) {}
GstCaps *gst_caps_from_string(const gchar *s) { return NULL; }
GstCaps *gst_caps_new_simple(const gchar *m, const gchar *f, ...) { return NULL; }
void gst_caps_unref(GstCaps *c) {}
GstClock *gst_element_get_clock(GstElement *e) { return NULL; }
GstClockTime gst_clock_get_time(GstClock *c) { return 0; }
GstClockTime gst_element_get_base_time(GstElement *e) { return 0; }
GstClock *gst_system_clock_obtain(void) { return NULL; }
void gst_pipeline_use_clock(GstElement *p, GstClock *c) {}
gboolean gst_element_link_many(GstElement *e1, ...) { return 1; }
void gst_bin_add_many(GstElement *b, ...) {}
void gst_bin_remove(GstElement *b, GstElement *e) {}
GstElement *gst_bin_get_by_name(GstElement *b, const gchar *n) { return NULL; }
void gst_object_unref(gpointer o) {}
void gst_object_ref(gpointer o) {}
GstEvent *gst_event_new_custom(GstEventType t, GstStructure *s) { return NULL; }
GstStructure *gst_structure_new_empty(const gchar *n) { return NULL; }
gboolean gst_element_send_event(GstElement *e, GstEvent *ev) { return 0; }
const gchar *gst_element_state_get_name(GstState s) { return "NULL"; }
GstFlowReturn gst_app_src_push_buffer(GstElement *a, GstBuffer *b) { return GST_FLOW_OK; }
void g_object_set(gpointer o, const gchar *p, ...) {}
void g_signal_connect(gpointer i, const gchar *s, void *h, gpointer d) {}
void g_free(gpointer m) { free(m); }
void g_error_free(GError *e) { if (e) free(e); }
