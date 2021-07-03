#include "config.h"
#include <epan/packet.h>

#define FOO_PORT 1234

static int proto_foo = -1;

static int hf_foo_pdu_type = -1;
//static int hf_foo_flags = -1;
static int hf_foo_nickSrcSize = -1;
static int hf_foo_nickSrc = -1;
static int hf_foo_nickDstSize = -1;
static int hf_foo_nickDst = -1;
static int hf_foo_roomSize = -1;
static int hf_foo_room = -1;
static int hf_foo_messageSize = -1;
static int hf_foo_message = -1;
static int hf_foo_sequenceno = -1;
static int hf_foo_initialip = -1;

static gint ett_foo = -1;


static const value_string packettypenames[] = {
    { 1, "HELLO" },
    { 2, "BYE" },
    { 3, "MSG" },
    { 4, "PRIV" },
    { 5, "NICK" },
    { 6, "LIST" },
    { 7, "QUIT" },
    { 8, "ROOM" },
    { 9, "ACK_HELLO" },
    { 10, "ACK_BYE" },
    { 11, "ACK_MSG" },
    { 12, "ACK_PRIV" },
    { 13, "ACK_NICK" },
    { 14, "ACK_LIST" },
    { 15, "ACK_QUIT" },
    { 16, "ACK_ROOM" },
    { 0, "NULL" }
};


static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    gint msglen = 0;
    guint8 packet_type = tvb_get_guint8(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUNFOO");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
             val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);

    /*PACKET_TYPE*/
    proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*NICK_SRC size*/
    msglen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_nickSrcSize, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*NICK_SRC*/
    proto_tree_add_item(foo_tree, hf_foo_nickSrc, tvb, offset, msglen, ENC_BIG_ENDIAN);
    offset += msglen;

    /*NICK_DST size*/
    msglen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_nickDstSize, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*NICK_DST*/
    proto_tree_add_item(foo_tree, hf_foo_nickDst, tvb, offset, msglen, ENC_BIG_ENDIAN);
    offset += msglen;

    /*ROOM name size*/
    msglen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_roomSize, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*ROOM name*/
    proto_tree_add_item(foo_tree, hf_foo_room, tvb, offset, msglen, ENC_BIG_ENDIAN);
    offset += msglen;

    /*MESSAGE size*/
    msglen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_messageSize, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*MESSAGE*/
    proto_tree_add_item(foo_tree, hf_foo_message, tvb, offset, msglen, ENC_BIG_ENDIAN);
    offset += msglen;


    return tvb_captured_length(tvb);
}


void
proto_register_foo(void)
{

    static hf_register_info hf[] = {
        { &hf_foo_pdu_type,
            { "QUNFOO PDU Type", "qunfoo.type",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },

        { &hf_foo_nickSrcSize,
            { "QUNFOO NICK_SRC Size", "qunfoo.nickSrcSize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_nickSrc,
            { "QUNFOO NICK_SRC", "qunfoo.nickSrc",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_nickDstSize,
            { "QUNFOO NICK_DST Size", "qunfoo.nickDstSize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_nickDst,
            { "QUNFOO NICK_DST", "qunfoo.nickDst",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_roomSize,
            { "QUNFOO ROOM Size", "qunfoo.roomSize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_room,
            { "QUNFOO ROOM", "qunfoo.room",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_messageSize,
            { "QUNFOO MESSAGE Size", "qunfoo.messageSize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_message,
            { "QUNFOO MESSAGE", "qunfoo.message",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_foo_sequenceno,
            { "QUNFOO PDU Sequence Number", "qunfoo.seqn",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_initialip,
            { "QUNFOO PDU Initial IP", "qunfoo.initialip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_foo
    };

    proto_foo = proto_register_protocol (
        "QUNFOO Protocol", /* name        */
        "QUNFOO",          /* short_name  */
        "qunfoo"           /* filter_name */
        );

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
