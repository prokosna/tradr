use prost::Message;
use tradr_core::{
    Ack, BrowseCodec, BrowseDomainError, BrowseMessage, ContentHash, Delete, Mkdir, RelPath,
    RelPathError, Rename, ShareId, WriteFile, WriteMode,
};
use tradr_proto::browse::ProtoBrowseCodec;

const A_VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

#[test]
fn round_trip_each_of_the_five_messages() {
    let codec = ProtoBrowseCodec::new(1024 * 1024);
    let share_id: ShareId = A_VALID_V7.parse().unwrap();

    let messages = vec![
        BrowseMessage::WriteFile(WriteFile {
            share_id,
            path: RelPath::new("dir/write.dat").unwrap(),
            size: 4096,
            content_hash: ContentHash::from_bytes([0x42; 32]),
            mode: WriteMode::CreateNew,
        }),
        BrowseMessage::Mkdir(Mkdir {
            share_id,
            path: RelPath::new("dir/new_folder").unwrap(),
            parents: true,
        }),
        BrowseMessage::Delete(Delete {
            share_id,
            path: RelPath::new("dir/remove_me").unwrap(),
            recursive: true,
        }),
        BrowseMessage::Rename(Rename {
            share_id,
            from: RelPath::new("dir/from.txt").unwrap(),
            to: RelPath::new("dir/to.txt").unwrap(),
        }),
        BrowseMessage::Ack(Ack {
            request_id: "req-abc-123".to_string(),
        }),
    ];

    for msg in messages {
        let encoded = codec.encode_frame(&msg, 1024 * 1024).unwrap();
        let (decoded, consumed) = codec
            .decode_frame(&encoded, 1024 * 1024)
            .unwrap()
            .expect("frame must be complete");
        assert_eq!(decoded, msg);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn write_file_followed_by_raw_bytes_leaves_bytes_and_retains_no_state() {
    let codec = ProtoBrowseCodec::new(1024 * 1024);
    let share_id: ShareId = A_VALID_V7.parse().unwrap();
    let write_file = BrowseMessage::WriteFile(WriteFile {
        share_id,
        path: RelPath::new("upload.bin").unwrap(),
        size: 100,
        content_hash: ContentHash::from_bytes([0x55; 32]),
        mode: WriteMode::Overwrite,
    });
    let encoded1 = codec.encode_frame(&write_file, 1024 * 1024).unwrap();

    let raw_bytes = vec![0x99u8; 100];
    let mut combined = encoded1.clone();
    combined.extend_from_slice(&raw_bytes);

    let (decoded1, consumed1) = codec
        .decode_frame(&combined, 1024 * 1024)
        .unwrap()
        .expect("write frame must be complete");
    assert_eq!(decoded1, write_file);
    assert_eq!(consumed1, encoded1.len());
    assert_eq!(&combined[consumed1..], &raw_bytes);

    let ack = BrowseMessage::Ack(Ack {
        request_id: "ack-999".to_string(),
    });
    let encoded2 = codec.encode_frame(&ack, 1024 * 1024).unwrap();

    // Verify unconsumed bytes do not poison or shift decoding of a subsequent frame.
    let mut second_slice = raw_bytes;
    second_slice.extend_from_slice(&encoded2);
    let (decoded2, consumed2) = codec
        .decode_frame(&second_slice[100..], 1024 * 1024)
        .unwrap()
        .expect("second frame must decode cleanly");
    assert_eq!(decoded2, ack);
    assert_eq!(consumed2, encoded2.len());
}

#[test]
fn two_frames_concatenated_decode_one_at_a_time() {
    let codec = ProtoBrowseCodec::new(1024 * 1024);
    let share_id: ShareId = A_VALID_V7.parse().unwrap();
    let mkdir = BrowseMessage::Mkdir(Mkdir {
        share_id,
        path: RelPath::new("dir_a").unwrap(),
        parents: false,
    });
    let ack = BrowseMessage::Ack(Ack {
        request_id: "ack-1".to_string(),
    });
    let enc1 = codec.encode_frame(&mkdir, 1024 * 1024).unwrap();
    let enc2 = codec.encode_frame(&ack, 1024 * 1024).unwrap();

    let mut combined = enc1.clone();
    combined.extend_from_slice(&enc2);

    let (dec1, consumed1) = codec
        .decode_frame(&combined, 1024 * 1024)
        .unwrap()
        .expect("first frame must decode");
    assert_eq!(dec1, mkdir);
    assert_eq!(consumed1, enc1.len());

    let remainder = &combined[consumed1..];
    let (dec2, consumed2) = codec
        .decode_frame(remainder, 1024 * 1024)
        .unwrap()
        .expect("second frame must decode");
    assert_eq!(dec2, ack);
    assert_eq!(consumed2, enc2.len());

    let empty = &remainder[consumed2..];
    assert!(empty.is_empty());
    assert!(codec.decode_frame(empty, 1024 * 1024).unwrap().is_none());
}

#[test]
fn slice_cut_one_byte_short_answers_none_and_whole_frame_succeeds() {
    let codec = ProtoBrowseCodec::new(1024 * 1024);
    let ack = BrowseMessage::Ack(Ack {
        request_id: "req-partial".to_string(),
    });
    let enc = codec.encode_frame(&ack, 1024 * 1024).unwrap();
    assert!(enc.len() > 1);

    let short = &enc[..enc.len() - 1];
    let res_short = codec.decode_frame(short, 1024 * 1024).unwrap();
    assert!(res_short.is_none());

    let (dec, consumed) = codec
        .decode_frame(&enc, 1024 * 1024)
        .unwrap()
        .expect("full frame must decode");
    assert_eq!(dec, ack);
    assert_eq!(consumed, enc.len());
}

#[test]
fn invalid_wire_fields_are_refused() {
    let codec = ProtoBrowseCodec::new(1024 * 1024);

    let wire_unspecified = tradr_proto::v1::WriteFile {
        share_id: A_VALID_V7.to_string(),
        path: "test.txt".to_string(),
        size: 10,
        content_hash: vec![0u8; 32],
        mode: tradr_proto::v1::WriteMode::Unspecified as i32,
    };
    let err_unspecified = tradr_proto::browse::write_file_from_wire(wire_unspecified.clone())
        .expect_err("WriteMode::Unspecified must be refused");
    assert_eq!(err_unspecified, BrowseDomainError::InvalidWriteMode);

    let encoded_unspecified =
        tradr_proto::framing::encode_frame(0x46, &wire_unspecified.encode_to_vec(), 1024 * 1024)
            .unwrap();
    let err_codec_unspecified = codec
        .decode_frame(&encoded_unspecified, 1024 * 1024)
        .expect_err("decode_frame must refuse WriteMode::Unspecified");
    assert_eq!(err_codec_unspecified, BrowseDomainError::InvalidWriteMode);

    let wire_bad_hash = tradr_proto::v1::WriteFile {
        share_id: A_VALID_V7.to_string(),
        path: "test.txt".to_string(),
        size: 10,
        content_hash: vec![0u8; 31],
        mode: tradr_proto::v1::WriteMode::CreateNew as i32,
    };
    let err_bad_hash = tradr_proto::browse::write_file_from_wire(wire_bad_hash.clone())
        .expect_err("31-byte content hash must be refused");
    assert_eq!(err_bad_hash, BrowseDomainError::InvalidContentHash(31));

    let encoded_bad_hash =
        tradr_proto::framing::encode_frame(0x46, &wire_bad_hash.encode_to_vec(), 1024 * 1024)
            .unwrap();
    let err_codec_bad_hash = codec
        .decode_frame(&encoded_bad_hash, 1024 * 1024)
        .expect_err("decode_frame must refuse 31-byte content hash");
    assert_eq!(
        err_codec_bad_hash,
        BrowseDomainError::InvalidContentHash(31)
    );

    let wire_empty_delete = tradr_proto::v1::Delete {
        share_id: A_VALID_V7.to_string(),
        path: String::new(),
        recursive: false,
    };
    let err_empty_delete = tradr_proto::browse::delete_from_wire(wire_empty_delete.clone())
        .expect_err("empty path in Delete must be refused");
    assert_eq!(
        err_empty_delete,
        BrowseDomainError::InvalidRelPath(RelPathError::Empty)
    );

    let encoded_empty_delete =
        tradr_proto::framing::encode_frame(0x48, &wire_empty_delete.encode_to_vec(), 1024 * 1024)
            .unwrap();
    let err_codec_empty_delete = codec
        .decode_frame(&encoded_empty_delete, 1024 * 1024)
        .expect_err("decode_frame must refuse empty path in Delete");
    assert_eq!(
        err_codec_empty_delete,
        BrowseDomainError::InvalidRelPath(RelPathError::Empty)
    );

    // 4. Unknown WriteMode integer is refused
    let wire_unknown_mode = tradr_proto::v1::WriteFile {
        share_id: A_VALID_V7.to_string(),
        path: "test.txt".to_string(),
        size: 10,
        content_hash: vec![0u8; 32],
        mode: 99,
    };
    let err_unknown_mode = tradr_proto::browse::write_file_from_wire(wire_unknown_mode)
        .expect_err("unknown WriteMode must be refused");
    assert_eq!(err_unknown_mode, BrowseDomainError::InvalidWriteMode);

    // 5. Empty path in Mkdir is refused
    let wire_empty_mkdir = tradr_proto::v1::Mkdir {
        share_id: A_VALID_V7.to_string(),
        path: String::new(),
        parents: false,
    };
    let err_empty_mkdir = tradr_proto::browse::mkdir_from_wire(wire_empty_mkdir)
        .expect_err("empty path in Mkdir must be refused");
    assert_eq!(
        err_empty_mkdir,
        BrowseDomainError::InvalidRelPath(RelPathError::Empty)
    );

    // 6. Empty from or to in Rename is refused
    let wire_empty_from = tradr_proto::v1::Rename {
        share_id: A_VALID_V7.to_string(),
        from: String::new(),
        to: "dest.txt".to_string(),
    };
    let err_empty_from = tradr_proto::browse::rename_from_wire(wire_empty_from)
        .expect_err("empty from path in Rename must be refused");
    assert_eq!(
        err_empty_from,
        BrowseDomainError::InvalidRelPath(RelPathError::Empty)
    );

    let wire_empty_to = tradr_proto::v1::Rename {
        share_id: A_VALID_V7.to_string(),
        from: "src.txt".to_string(),
        to: String::new(),
    };
    let err_empty_to = tradr_proto::browse::rename_from_wire(wire_empty_to)
        .expect_err("empty to path in Rename must be refused");
    assert_eq!(
        err_empty_to,
        BrowseDomainError::InvalidRelPath(RelPathError::Empty)
    );

    // 7. Empty path in WriteFile is refused
    let wire_empty_write = tradr_proto::v1::WriteFile {
        share_id: A_VALID_V7.to_string(),
        path: String::new(),
        size: 10,
        content_hash: vec![0u8; 32],
        mode: tradr_proto::v1::WriteMode::CreateNew as i32,
    };
    let err_empty_write = tradr_proto::browse::write_file_from_wire(wire_empty_write)
        .expect_err("empty path in WriteFile must be refused");
    assert_eq!(
        err_empty_write,
        BrowseDomainError::InvalidRelPath(RelPathError::Empty)
    );
}
