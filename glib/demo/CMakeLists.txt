set(poppler_glib_demo_SRCS
  main.c
  find.c
  fonts.c
  forms.c
  info.cc
  images.c
  links.c
  outline.c
  page.c
  print.c
  render.c
  text.c
  transitions.c
  utils.c
  annots.c
  attachments.c
  layers.c
  selections.c
  taggedstruct.c
  signature.c
  annots.h
  attachments.h
  find.h
  fonts.h
  forms.h
  images.h
  info.h
  layers.h
  links.h
  outline.h
  page.h
  print.h
  render.h
  selections.h
  signature.h
  taggedstruct.h
  text.h
  transitions.h
  utils.h
)
poppler_add_test(poppler-glib-demo BUILD_GTK_TESTS ${poppler_glib_demo_SRCS})

target_link_libraries(poppler-glib-demo ${CAIRO_LIBRARIES} poppler-glib PkgConfig::GTK3)
if (INSTALL_GLIB_DEMO)
  install(TARGETS poppler-glib-demo DESTINATION bin)
endif ()
