#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>

//copy this from iw
#include "nl80211.h"

static int expectedId;

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
};

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

void parse_he_info(struct nlattr *nl_iftype)
{
	int i;
    struct nlattr *tb_iftype[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
	struct nlattr *tb_iftype_flags[NL80211_IFTYPE_MAX + 1];
	char *iftypes[NUM_NL80211_IFTYPES] = {
		"Unspec", "Adhoc", "Station", "AP", "AP/VLAN", "WDS", "Monitor",
		"Mesh", "P2P/Client", "P2P/Go", "P2P/Device", "OCB", "NAN",
	};

    printf("Got WIPHY IFTYPE ====>.\n");
    nla_parse(tb_iftype, NL80211_BAND_IFTYPE_ATTR_MAX, nla_data(nl_iftype), nla_len(nl_iftype), NULL);

	if (!tb_iftype[NL80211_BAND_IFTYPE_ATTR_IFTYPES])
		return;

	if (nla_parse_nested(tb_iftype_flags, NL80211_IFTYPE_MAX, tb_iftype[NL80211_BAND_IFTYPE_ATTR_IFTYPES], NULL))
		return;

	printf("\t\tHE Iftypes:");
	for (i = 0; i < NUM_NL80211_IFTYPES; i++)
		if (nla_get_flag(tb_iftype_flags[i]) && iftypes[i])
			printf(" %s", iftypes[i]);
	printf("\n");

    return;
}

static int nlCallback(struct nl_msg* msg, void* arg)
{
    struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct nl80211_state *state = (struct nl80211_state *)arg;

    printf("Got NL CALL BACK.\n");

    if (ret_hdr->nlmsg_type != state->nl80211_id) {
        printf("invalid nlmsg id");
        return NL_STOP;
    }

    struct genlmsghdr *gnlh = (struct genlmsghdr*) nlmsg_data(ret_hdr);

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
        int rem_band;
        struct nlattr *nl_band;
        struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

        printf("Got WIPHY BANDS.\n");
		nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
            printf("Got WIPHY BANDS ====>.\n");

            nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
            if (tb_band[NL80211_BAND_ATTR_IFTYPE_DATA]) {
                struct nlattr *nl_iftype;
                int rem_band_iftype;

                printf("Got WIPHY IFTYPE.\n");
                nla_for_each_nested(nl_iftype, tb_band[NL80211_BAND_ATTR_IFTYPE_DATA], rem_band_iftype) {
                    parse_he_info(nl_iftype);
                }
            }
        }
    }

	return NL_SKIP;
}

static int phy_lookup(const char *name)
{
	char buf[200];
	int fd, pos;

	snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", name);

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;
	pos = read(fd, buf, sizeof(buf) - 1);
	if (pos < 0) {
		close(fd);
		return -1;
	}
	buf[pos] = '\0';
	close(fd);
	return atoi(buf);
}

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	nl_socket_free(state->nl_sock);
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

int run_nl80211(struct nl80211_state *state, enum command_identify_by idby, const char *name)
{
	int err = -1;
    int devidx = -1;
	struct nl_cb *cb = NULL;
	struct nl_cb *s_cb = NULL;
	struct nl_msg *msg = NULL;
    int flags = 0;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return -1;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb || !s_cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		goto out_free_msg;
	}

	genlmsg_put(msg, 0, 0, state->nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);

    switch (idby) {
        case CIB_PHY:
            devidx = phy_lookup(name);
            NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
            break;
        case CIB_NETDEV:
            devidx = if_nametoindex(name);
            NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
            break;
        default:
            break;
    }

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nlCallback, state);
	nl_socket_set_cb(state->nl_sock, s_cb);

	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0) {
		fprintf(stderr, "failed to nl_send_auto_complete\n");
		goto out;
    }

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	while (err > 0)
		nl_recvmsgs(state->nl_sock, cb);

 out:
	nl_cb_put(cb);
 out_free_msg:
	nlmsg_free(msg);
	return err;
 nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return -1;
}

int got_wiphy(enum command_identify_by idby, const char *name)
{
    int err = -1;
	struct nl80211_state nlstate = {0};

	err = nl80211_init(&nlstate);
	if (err)
		return -1;

    err = run_nl80211(&nlstate, idby, name);

	nl80211_cleanup(&nlstate);

    return err;
}

int main(void)
{
    got_wiphy(CIB_PHY, "phy0");

    return 0;
}

