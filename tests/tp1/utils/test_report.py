from unittest.mock import patch, MagicMock, mock_open
import pytest
import os
from src.tp1.utils.report import Report


@pytest.fixture
def report_instance():
    capture_mock = MagicMock()
    capture_mock.get_all_protocols.return_value = {"TCP": 10, "UDP": 5, "ICMP": 2}
    filename = "test_report.pdf"
    summary = "Test Summary"
    return Report(capture_mock, filename, summary)


def test_init(report_instance):
    # Then
    assert report_instance.title == "TITRE DU RAPPORT"
    assert report_instance.summary == "Test Summary"
    assert report_instance.filename == "test_report.pdf"


def test_concat_report(report_instance):
    # Given
    report_instance.title = "TITRE"
    report_instance.summary = "RESUME"
    report_instance.array = "TABLEAU"
    report_instance.graph = "GRAPHIQUE"
    
    # When
    result = report_instance.concat_report()
    
    # Then
    assert result == "TITRERESUMECALTABLEAUGRAPHIQUE"


@patch("builtins.open", new_callable=mock_open)
def test_save(mock_file, report_instance):
    # Given
    report_instance.concat_report = MagicMock(return_value="CONTENT")
    
    # When
    report_instance.save("output.pdf")
    
    # Then
    mock_file.assert_called_once_with("test_report.pdf", "w")
    mock_file().write.assert_called_once_with("CONTENT")


@patch.object(Report, "_generate_graph")
def test_generate_graph(mock_generate_graph, report_instance):
    # Given
    mock_generate_graph.return_value = "GRAPH_DATA"
    
    # When
    report_instance.generate("graph")
    
    # Then
    assert report_instance.graph == "GRAPH_DATA"
    mock_generate_graph.assert_called_once()


@patch.object(Report, "_generate_array")
def test_generate_array(mock_generate_array, report_instance):
    # Given
    mock_generate_array.return_value = "ARRAY_DATA"
    
    # When
    report_instance.generate("array")
    
    # Then
    assert report_instance.array == "ARRAY_DATA"
    mock_generate_array.assert_called_once()


def test_generate_invalid_param(report_instance):
    # When/Then
    with pytest.raises(ValueError, match="Invalid parameter: invalid"):
        report_instance.generate("invalid")
