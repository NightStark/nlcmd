#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

//copy this from iw
#include "nl80211.h"

static int expectedId;

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
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

    if (ret_hdr->nlmsg_type != expectedId)
    {
        // what is this??
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

int got_wiphy(enum command_identify_by idby, const char *name)
{
    int ret;
    //allocate socket
    struct nl_sock* sk = nl_socket_alloc();

	nl_socket_set_buffer_size(sk, 8192, 8192);

    //connect to generic netlink
    genl_connect(sk);

    //find the nl80211 driver ID
    expectedId = genl_ctrl_resolve(sk, "nl80211");

    //attach a callback
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nlCallback, NULL);

    //allocate a message
    struct nl_msg* msg = nlmsg_alloc();

    enum nl80211_commands cmd = NL80211_CMD_GET_WIPHY;
    int devidx;
    int flags = 0;

    if (idby == CIB_NETDEV) {
        devidx = if_nametoindex(name);
    } else if (idby == CIB_PHY) {
        devidx = phy_lookup(name);
    }

    // setup the message
    genlmsg_put(msg, 0, 0, expectedId, 0, flags, cmd, 0);

    //add message attributes
    if (idby == CIB_NETDEV) {
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
    } else if (idby == CIB_PHY) {
        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
    }

    //send the messge (this frees it)
    ret = nl_send_auto_complete(sk, msg);

    //block for message to return
    nl_recvmsgs_default(sk);

    return 0;

nla_put_failure:
    nlmsg_free(msg);

    return 1;
}

int main(void)
{
    got_wiphy(CIB_PHY, "phy0");

    return 0;
}

