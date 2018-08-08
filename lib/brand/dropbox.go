package brand

// Dropbox brand properties.
func Dropbox() *Brand {
	name := "dropbox"
	original := []string{"dropbox"}
	whitelist := []string{
		"db.tt", "dropbox.com", "dropboxapi.com", "dropboxbusiness.com",
		"dropboxdocs.com", "dropboxforums.com", "dropboxforum.com",
		"dropboxinsiders.com", "dropboxmail.com", "dropboxpartners.com",
		"dropboxstatic.com", "dropbox.zendesk.com", "getdropbox.com",
	}
	suspicious := []string{
		"eropbox", "fropbox", "lropbox", "tropbox", "dsopbox", "dpopbox",
		"dvopbox", "dzopbox", "dbopbox", "d2opbox", "drnpbox", "drmpbox",
		"drkpbox", "drgpbox", "droqbox", "drorbox", "drotbox", "droxbox",
		"dro0box", "dropcox", "dropfox", "dropjox", "droprox", "dropbnx",
		"dropbmx", "dropbkx", "dropbgx", "dropboy", "dropboz", "dropbop",
		"dropboh", "dropbo8", "dropb0x", "dr0pbox", "clropbox", "dropibox",
		"dropdox", "dr0pb0x", "dlropbox", "diropbox", "bropbox", "droplbox",
		"droppbox", "drop0box", "dfropbox", "dr4opbox", "droipbox", "droopbox",
		"dreopbox", "dropbo9x", "dr9opbox", "dr5opbox", "drokpbox", "dtropbox",
		"drompbox", "dropbolx", "dropboix", "dropbo0x", "driopbox", "dropb0ox",
		"drpopbox", "drlopbox", "dro0pbox", "dropgbox", "dropbgox", "drtopbox",
		"deropbox", "dropmbox", "dropbiox", "dropblox", "dropbokx", "dropobox",
		"dropnbox", "drolpbox", "ddropbox", "drkopbox", "dropbnox", "drophbox",
		"dropb9ox", "d4ropbox", "dropbkox", "dropbopx", "dropbhox", "dropvbox",
		"drfopbox", "drdopbox", "d5ropbox", "dropbpox", "dro9pbox", "dr0opbox",
		"dropbvox", "dopbox", "dropbo", "drpbox", "dropbx", "drobox", "dropox",
		"ropbox", "dropboox", "dropbbox", "drropbox", "dr9pbox", "drlpbox",
		"dtopbox", "dfopbox", "ddopbox", "d5opbox", "dropblx", "sropbox",
		"dropbod", "deopbox", "dropb9x", "dropboc", "xropbox", "d4opbox",
		"dropbpx", "dropgox", "dropbos", "dripbox", "droobox", "drppbox",
		"dropvox", "rropbox", "drolbox", "drombox", "dropnox", "dropbix",
		"drophox", "rdopbox", "dorpbox", "drpobox", "drobpox", "dropobx",
		"dropbxo", "dropbax", "dropbex", "drupbox", "dropbux", "drapbox",
		"drepbox", "dropboxcom", "xn--drpbox-xxa", "xn--drpbx-scec",
		"xn--drpbx-kyec", "xn--drobox-52b", "xn--dropbx-fxa", "xn--dropbx-0qf",
		"xn--dopbox-p6c", "xn--drpbox-cxa", "xn--dropox-eof", "xn--ropbox-vug",
		"xn--dropbo-gfg", "xn--dropbo-n77b", "xn--dropbx-mqc", "xn--drpbox-jqc",
		"xn--drpbox-4wb", "xn--drobox-ycf", "xn--drpbox-qpg", "xn--drpbx-jsfc",
		"xn--dropbx-0qf", "xn--drpbox-j0e", "xn--drobox-y0e", "xn--ropbox-vgh",
		"xn--drpbx-kuac", "xn--dopbox-35c", "xn--drpbx-vobc", "xn--drpbox-ql8b",
		"xn--drpbox-xqf", "xn--drpbox-4l8b", "xn--ropbox-92a", "xn--dropbx-tpg",
		"xn--dopbox-pof", "xn--dropox-scd", "xn--drpbox-j0e", "xn--drobox-drf",
		"xn--drpbx-381bc", "xn--dopbox-355b", "xn--dropbx-7l8b",
		"xn--drpbox-xqf", "xn--drpbx-7dcc", "xn--drobox-kza", "xn--dropbox-9ke",
		"xn--dropbx-m0e", "xn--dropox-sxc", "xn--drpbx-mkgc", "xn--dropox-stf",
		"xn--dropbx-fmh", "xn--dropbx-0xa", "xn--drpbx-scec", "xn--ropbox-hyc",
		"xn--dropbx-tl8b", "xn--dropbx-7wb", "xn--dopbox-w5c", "xn--dropbo-gsf",
		"xn--drpbx-1tac", "xn--dropbx-m0e", "xn--drpbx-kyec", "xn--drpbx-g91bc",
		"xn--drpbox-cmh",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
