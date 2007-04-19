#!/bin/sh

STYLESHEET=/usr/share/xml/docbook/stylesheet/nwalsh/current/xhtml/docbook.xsl
WEBSITE=/srv/www/html
PROJECTS="web docs docs-fr"
HOMEDIR=/home/judas_iscariote
SVN_BIN=/usr/bin/svn

publish() {
    case $1 in
	*.xml)
	    b=${1%.*}

	    if [ -f $WEBSITE/$b.htm ]; then
		b=$b.htm
		f="$WEBSITE/$b"
	    else
		b=$b.html
		f="$WEBSITE/$b"
	    fi

	    echo "Converting $1 from XML to HTML ($b) ..."

	    xmllint --valid --noout $1 && xsltproc --output $f --stringparam html.stylesheet html.css --stringparam ulink.target _self -param toc.section.depth 3 $STYLESHEET $1
	    chmod g+w $f
	    ;;
	*)
	    cp $1 $WEBSITE/$1
	    chmod g+w $WEBSITE/$1
	    ;;
    esac

}

for project in $PROJECTS; do
    cd $HOMEDIR/$project
    $SVN_BIN  update --non-interactive | while read UA file; do 
	case $UA in
	    U|P|G)
		publish $file
		;;
	    A)
		[ -d $file ] && mkdir $WEBSITE/$file || publish $file
		;;
	esac
    done
done
