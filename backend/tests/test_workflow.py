from backend.workflow import pipeline_states


UPLOAD_ONE = "11111111-1111-4111-8111-111111111111"
UPLOAD_TWO = "22222222-2222-4222-8222-222222222222"


def record(record_id, source_id, offset, length=10, file_type="JPEG"):
    return {
        "id": record_id,
        "source_id": source_id,
        "file_type": file_type,
        "offset": offset,
        "length": length,
    }


def test_unrelated_recovery_does_not_mark_current_candidate_pipeline_complete():
    first = record("first", UPLOAD_ONE, 0)
    other = record("other", UPLOAD_TWO, 20)
    records = [first, other]

    states = pipeline_states(records, other, recovery_exists=False, recovery_verified=False)

    assert states == (True, True, True, True, False, False, False, False)


def test_selected_candidate_with_adjacent_verified_recovery_shows_completed_stages():
    first = record("first", UPLOAD_ONE, 0)
    second = record("second", UPLOAD_ONE, 10)
    records = [first, second]

    states = pipeline_states(records, second, recovery_exists=True, recovery_verified=True)

    assert states == (True, True, True, True, True, True, True, True)


def test_legacy_or_same_name_different_uploads_do_not_show_compatibility():
    selected = record("legacy", "unknown-upload-id", 0)
    same_filename_other_upload = record("other", UPLOAD_TWO, 10)

    states = pipeline_states(
        [selected, same_filename_other_upload],
        selected,
        recovery_exists=False,
        recovery_verified=False,
    )

    assert states[4:] == (False, False, False, False)


def test_relationship_view_never_imports_candidate_specific_recovery_state():
    first = record("first", UPLOAD_ONE, 0)
    second = record("second", UPLOAD_ONE, 10)

    states = pipeline_states(
        [first, second],
        selected_record=None,
        recovery_exists=False,
        recovery_verified=False,
    )

    assert states[4] is True
    assert states[5:] == (False, False, False)
