// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Field-ordered encoding for the schema's interleaved oneof.
use super::{OwnMessageCopy, own_message_copy::Payload};
use prost::{
    DecodeError, Message,
    bytes::{Buf, BufMut},
    encoding::{self, DecodeContext, WireType},
};

impl Message for OwnMessageCopy {
    fn encode_raw(&self, buf: &mut impl BufMut) {
        if let Some(Payload::Item(value)) = &self.payload {
            encoding::message::encode(1, value, buf);
        }
        if let Some(value) = &self.source {
            encoding::message::encode(2, value, buf);
        }
        if let Some(value) = &self.target {
            encoding::message::encode(3, value, buf);
        }
        if self.created_at != 0 {
            encoding::int64::encode(4, &self.created_at, buf);
        }
        if self.expires_at != 0 {
            encoding::int64::encode(5, &self.expires_at, buf);
        }
        if let Some(Payload::Sent(value)) = &self.payload {
            encoding::message::encode(6, value, buf);
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError> {
        match tag {
            1 | 6 => Payload::merge(&mut self.payload, tag, wire, buf, ctx),
            2 => encoding::message::merge(wire, self.source.get_or_insert_default(), buf, ctx),
            3 => encoding::message::merge(wire, self.target.get_or_insert_default(), buf, ctx),
            4 => encoding::int64::merge(wire, &mut self.created_at, buf, ctx),
            5 => encoding::int64::merge(wire, &mut self.expires_at, buf, ctx),
            _ => encoding::skip_field(wire, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        self.payload.as_ref().map_or(0, Payload::encoded_len)
            + self.source.as_ref().map_or(0, |value| encoding::message::encoded_len(2, value))
            + self.target.as_ref().map_or(0, |value| encoding::message::encoded_len(3, value))
            + if self.created_at == 0 {
                0
            } else {
                encoding::int64::encoded_len(4, &self.created_at)
            }
            + if self.expires_at == 0 {
                0
            } else {
                encoding::int64::encoded_len(5, &self.expires_at)
            }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}
