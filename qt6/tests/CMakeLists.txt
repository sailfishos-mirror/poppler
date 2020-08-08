add_definitions(-DTESTDATADIR=\"${TESTDATADIR}\")

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ${CMAKE_CURRENT_BINARY_DIR}
)

macro(QT6_ADD_SIMPLETEST exe source)
  string(REPLACE "-" "" test_name ${exe})
  set(${test_name}_SOURCES
    ${source}
  )
  poppler_add_test(${exe} BUILD_QT6_TESTS ${${test_name}_SOURCES})
  target_link_libraries(${exe} poppler-qt6 Qt6::Widgets)
  if(MSVC)
    target_link_libraries(${exe} poppler ${poppler_LIBS})
  endif()
endmacro()

macro(QT6_ADD_QTEST exe source)
    string(REPLACE "-" "" test_name ${exe})
    set(${test_name}_SOURCES
      ${source}
    )
    poppler_add_unittest(${exe} BUILD_QT6_TESTS ${${test_name}_SOURCES})
    target_link_libraries(${exe} poppler-qt6 Qt6::Widgets Qt6::Test Qt6::Gui)
    if(MSVC)
      target_link_libraries(${exe} poppler ${poppler_LIBS})
    endif()
endmacro()


qt6_add_simpletest(test-poppler-qt6 test-poppler-qt6.cpp)
qt6_add_simpletest(test-password-qt6 test-password-qt6.cpp)
qt6_add_simpletest(test-render-to-file-qt6 test-render-to-file.cpp)
qt6_add_simpletest(poppler-qt6-forms poppler-forms.cpp)
qt6_add_simpletest(poppler-qt6-fonts poppler-fonts.cpp)
qt6_add_simpletest(poppler-qt6-attachments poppler-attachments.cpp)
qt6_add_simpletest(stress-poppler-qt6 stress-poppler-qt6.cpp)
qt6_add_simpletest(stress-poppler-dir-qt6 stress-poppler-dir.cpp)
qt6_add_simpletest(stress-threads-qt6 stress-threads-qt6.cpp)
qt6_add_simpletest(poppler-qt6-texts poppler-texts.cpp)
qt6_add_simpletest(poppler-qt6-page-labels poppler-page-labels.cpp)

qt6_add_qtest(check_qt6_attachments check_attachments.cpp)
qt6_add_qtest(check_qt6_dateConversion check_dateConversion.cpp)
qt6_add_qtest(check_qt6_fonts check_fonts.cpp)
qt6_add_qtest(check_qt6_links check_links.cpp)
qt6_add_qtest(check_qt6_annotations check_annotations.cpp)
qt6_add_qtest(check_qt6_metadata check_metadata.cpp)
qt6_add_qtest(check_qt6_optcontent check_optcontent.cpp)
qt6_add_qtest(check_qt6_forms check_forms.cpp)
qt6_add_qtest(check_qt6_pagelayout check_pagelayout.cpp)
qt6_add_qtest(check_qt6_pagemode check_pagemode.cpp)
qt6_add_qtest(check_qt6_password check_password.cpp)
qt6_add_qtest(check_qt6_permissions check_permissions.cpp)
qt6_add_qtest(check_qt6_search check_search.cpp)
qt6_add_qtest(check_qt6_actualtext check_actualtext.cpp)
qt6_add_qtest(check_qt6_lexer check_lexer.cpp)
qt6_add_qtest(check_qt6_goostring check_goostring.cpp)
qt6_add_qtest(check_qt6_object check_object.cpp)
qt6_add_qtest(check_qt6_stroke_opacity check_stroke_opacity.cpp)
qt6_add_qtest(check_qt6_utf_conversion check_utf_conversion.cpp)
qt6_add_qtest(check_qt6_outline check_outline.cpp)
if (NOT WIN32)
  qt6_add_qtest(check_qt6_pagelabelinfo check_pagelabelinfo.cpp)
  qt6_add_qtest(check_qt6_strings check_strings.cpp)
endif ()