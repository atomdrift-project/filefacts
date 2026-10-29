use super::days_from_civil;

#[test]
fn epoch_is_zero() {
    assert_eq!(days_from_civil(1970, 1, 1), Some(0));
}

#[test]
fn known_dates() {
    assert_eq!(days_from_civil(2000, 1, 1), Some(10_957));
    assert_eq!(days_from_civil(2024, 1, 1), Some(19_723));
}

#[test]
fn invalid_returns_none() {
    assert!(days_from_civil(2024, 0, 1).is_none());
    assert!(days_from_civil(2024, 13, 1).is_none());
    assert!(days_from_civil(2024, 2, 0).is_none());
    assert!(days_from_civil(2024, 2, 32).is_none());
}
